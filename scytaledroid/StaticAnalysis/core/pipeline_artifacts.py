"""Utilities for summarising and serialising detector pipeline outputs."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from ..analytics import build_finding_matrices, build_workload_profile
from .manifest_utils import build_manifest_evidence
from .findings import Badge, DetectorResult

if TYPE_CHECKING:  # pragma: no cover - typing imports only
    from .context import DetectorContext


@dataclass(frozen=True)
class PipelineArtifacts:
    """Container for derived metadata about a detector pipeline run."""

    results: tuple[DetectorResult, ...]
    trace: tuple[Mapping[str, object], ...]
    metrics: Mapping[str, Mapping[str, object]]
    summary: Mapping[str, object]
    reproducibility_bundle: Mapping[str, object]
    matrices: Mapping[str, Mapping[str, Mapping[str, int]]] = field(
        default_factory=dict
    )
    indicators: Mapping[str, float] = field(default_factory=dict)
    workload: Mapping[str, object] = field(default_factory=dict)


def build_pipeline_trace(
    results: Sequence[DetectorResult],
) -> tuple[Mapping[str, object], ...]:
    """Return a serialisable trace describing detector pipeline stages."""

    trace: list[Mapping[str, object]] = []
    for index, result in enumerate(results, start=1):
        entry: dict[str, object] = {
            "index": index,
            "section": result.section_key,
            "detector": result.detector_id,
            "status": result.status.value,
            "duration": float(result.duration_sec or 0.0),
        }

        severity_counts = Counter(
            finding.severity_gate.value for finding in result.findings
        )
        if severity_counts:
            entry["severity"] = {
                label: severity_counts[label]
                for label in ("P0", "P1", "P2", "NOTE")
                if severity_counts.get(label, 0)
            }
            entry["finding_count"] = int(sum(severity_counts.values()))
        elif result.findings:
            entry["finding_count"] = len(result.findings)

        metrics = _serialise_metrics(result.metrics)
        if metrics:
            entry["metrics"] = metrics

        notes: list[str] = []
        for note in result.notes:
            if isinstance(note, str):
                text = note.strip()
                if text:
                    notes.append(text)

        for key in ("skip_reason", "error"):
            value = metrics.get(key) if isinstance(metrics, Mapping) else None
            if isinstance(value, str):
                text = value.strip()
                if text and text not in notes:
                    notes.append(text)

        if notes:
            entry["notes"] = tuple(notes)

        trace.append(entry)

    return tuple(trace)


def collect_detector_metrics(
    results: Sequence[DetectorResult],
) -> Mapping[str, Mapping[str, object]]:
    """Return a mapping of detector identifier -> metrics payload."""

    metrics: dict[str, Mapping[str, object]] = {}
    for result in results:
        if result.metrics:
            metrics[result.detector_id] = dict(result.metrics)
    return metrics


def build_pipeline_summary(results: Sequence[DetectorResult]) -> Mapping[str, object]:
    """Build aggregate statistics describing the detector pipeline run."""

    total = len(results)
    executed = sum(1 for result in results if result.status is not Badge.SKIPPED)
    total_duration = sum(float(result.duration_sec or 0.0) for result in results)

    status_counts: Counter[str] = Counter(result.status.value for result in results)
    error_detectors: list[dict[str, object]] = []
    policy_fail_detectors: list[dict[str, object]] = []
    finding_fail_detectors: list[dict[str, object]] = []

    severity_counter: Counter[str] = Counter()
    for result in results:
        severity_counter.update(
            finding.severity_gate.value for finding in result.findings
        )
        metrics_payload = _serialise_metrics(result.metrics)
        error_text = _first_non_empty(
            metrics_payload.get("error"),
            *(note.strip() for note in result.notes if isinstance(note, str)),
        )
        if error_text and result.status is Badge.ERROR:
            error_detectors.append(
                {
                    "detector": result.detector_id,
                    "section": result.section_key,
                    "reason": error_text,
                }
            )
        elif result.status is Badge.FAIL:
            metrics_payload = _serialise_metrics(result.metrics)
            is_policy_gate = bool(metrics_payload.get("policy_gate", False))
            entry = {"detector": result.detector_id, "section": result.section_key}
            if is_policy_gate:
                policy_fail_detectors.append(entry)
            else:
                finding_fail_detectors.append(entry)

    total_findings = int(sum(severity_counter.values()))

    slowest_candidates = [
        {
            "detector": result.detector_id,
            "section": result.section_key,
            "duration_sec": round(float(result.duration_sec or 0.0), 2),
        }
        for result in results
        if (result.duration_sec or 0.0) > 0
    ]
    slowest = sorted(
        slowest_candidates,
        key=lambda item: item["duration_sec"],
        reverse=True,
    )[:3]

    skipped_details = []
    for result in results:
        if result.status is Badge.SKIPPED:
            metrics_payload = _serialise_metrics(result.metrics)
            reason = _first_non_empty(
                metrics_payload.get("skip_reason"),
                metrics_payload.get("error"),
                *(note.strip() for note in result.notes if isinstance(note, str)),
            )
            skipped_details.append(
                {
                    "detector": result.detector_id,
                    "section": result.section_key,
                    "reason": reason or "unspecified",
                }
            )

    summary: dict[str, object] = {
        "detector_total": total,
        "detector_executed": executed,
        "detector_skipped": total - executed,
        "status_counts": {key: int(value) for key, value in status_counts.items()},
        "severity_counts": {
            key: int(severity_counter[key])
            for key in ("P0", "P1", "P2", "NOTE")
            if severity_counter.get(key)
        },
        "total_findings": total_findings,
        "total_duration_sec": round(total_duration, 1),
    }

    if executed:
        summary["average_duration_sec"] = round(total_duration / executed, 2)

    if slowest:
        summary["slowest_detectors"] = slowest

    if error_detectors:
        summary["error_count"] = len(error_detectors)
        summary["error_detectors"] = error_detectors

    if policy_fail_detectors:
        summary["policy_fail_count"] = len(policy_fail_detectors)
        summary["policy_fail_detectors"] = policy_fail_detectors

    if finding_fail_detectors:
        summary["finding_fail_count"] = len(finding_fail_detectors)
        summary["finding_fail_detectors"] = finding_fail_detectors

    if skipped_details:
        summary["skipped_detectors"] = skipped_details

    return summary


def build_reproducibility_bundle(
    context: DetectorContext,
) -> Mapping[str, object]:
    """Construct a reproducibility bundle based on the detector context."""

    manifest_source = "androguard"
    semantics_source = "androguard"
    meta = context.metadata or {}
    if isinstance(meta, Mapping):
        manifest_source = str(meta.get("manifest_source") or manifest_source)
        semantics_source = str(meta.get("manifest_semantics_source") or semantics_source)

    bundle: dict[str, object] = {
        "manifest": context.manifest_summary.to_dict(),
        "manifest_flags": context.manifest_flags.to_dict(),
        "permissions": context.permissions.to_dict(),
        "components": context.components.to_dict(),
        "exported_components": context.exported_components.to_dict(),
        "manifest_evidence": {
            "source_manifest": manifest_source,
            "source_semantics": semantics_source,
            "components": build_manifest_evidence(
                context.manifest_root,
                source_manifest=manifest_source,
                source_semantics=semantics_source,
            ),
        },
        "hashes": dict(context.hashes),
        "features": list(context.features),
        "libraries": list(context.libraries),
        "signatures": list(context.signatures),
    }

    if context.metadata:
        safe_meta: dict[str, object] = {}
        for key, value in context.metadata.items():
            label = str(key)
            if value is None or isinstance(value, (str, int, float, bool)):
                safe_meta[label] = value
            else:
                safe_meta[label] = str(value)
        bundle["metadata"] = safe_meta

    network_security_policy = context.network_security_policy
    if network_security_policy and (
        getattr(network_security_policy, "source_path", None)
        or getattr(network_security_policy, "raw_xml_hash", None)
    ):
        bundle["network_security_config"] = network_security_policy.to_dict()

    string_index = getattr(context, "string_index", None)
    if string_index is not None and hasattr(string_index, "is_empty"):
        if not string_index.is_empty():
            bundle["string_index"] = _summarise_string_index(string_index)

    metrics_map = collect_detector_metrics(getattr(context, "intermediate_results", tuple()))
    if metrics_map:
        bundle["detector_metrics"] = {
            key: _serialise_metrics(value) for key, value in metrics_map.items()
        }

    diff_basis = build_diff_basis(context)
    bundle["diff_basis"] = diff_basis
    bundle["diff_basis_hash"] = sha256(
        json.dumps(diff_basis, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return bundle


def build_diff_basis(context: DetectorContext) -> Mapping[str, object]:
    """Generate a deterministic basis for report diffing."""

    basis: dict[str, object] = {
        "manifest_flags": context.manifest_flags.to_dict(),
        "permissions": {
            "declared": sorted(context.permissions.declared),
            "dangerous": sorted(context.permissions.dangerous),
            "custom": sorted(context.permissions.custom),
        },
        "exported_components": {
            key: sorted(values)
            for key, values in context.exported_components.to_dict().items()
        },
    }

    summary = context.manifest_summary
    basis["manifest"] = {
        "version_name": summary.version_name,
        "version_code": summary.version_code,
        "min_sdk": summary.min_sdk,
        "target_sdk": summary.target_sdk,
        "compile_sdk": summary.compile_sdk,
    }

    custom_definitions = getattr(context.permissions, "custom_definitions", {})
    if custom_definitions:
        basis["custom_permissions"] = {
            name: {
                "protection_levels": tuple(
                    str(value)
                    for value in definition.get("protection_levels", ())
                    if value
                ),
                "group": definition.get("group"),
            }
            for name, definition in custom_definitions.items()
        }

    metrics_map = {
        result.detector_id: dict(result.metrics)
        for result in getattr(context, "intermediate_results", tuple())
        if result.metrics and result.detector_id != "correlation_engine"
    }

    network_metrics = metrics_map.get("network_surface")
    if isinstance(network_metrics, Mapping):
        surface = network_metrics.get("surface")
        hosts: dict[str, Sequence[str]] = {}
        if isinstance(surface, Mapping):
            host_map = surface.get("hosts")
            if isinstance(host_map, Mapping):
                hosts = {
                    kind: sorted(map(str, host_map.get(kind, ())))
                    for kind in ("http", "https")
                }
        nsc = network_metrics.get("NSC")
        basis["network_surface"] = {
            "hosts": hosts,
            "policy": nsc if isinstance(nsc, Mapping) else {},
        }

    secrets_metrics = metrics_map.get("secrets_credentials")
    if isinstance(secrets_metrics, Mapping):
        secret_types = secrets_metrics.get("secret_types")
        if isinstance(secret_types, Mapping):
            basis["secrets"] = {
                str(name): int(data.get("found", 0))
                for name, data in secret_types.items()
                if isinstance(data, Mapping)
            }

    storage_metrics = metrics_map.get("storage_backup")
    if isinstance(storage_metrics, Mapping):
        basis["storage"] = {
            "allow_backup": storage_metrics.get("allow_backup"),
            "legacy_external_storage": storage_metrics.get(
                "legacy_external_storage"
            ),
            "sensitive_keys": storage_metrics.get("sensitive_keys", 0),
        }

    crypto_metrics = metrics_map.get("crypto_hygiene")
    if isinstance(crypto_metrics, Mapping):
        basis["crypto"] = {
            str(key): int(value)
            for key, value in crypto_metrics.items()
            if isinstance(value, (int, float))
        }

    if metrics_map:
        basis["detector_metrics"] = {
            key: _serialise_metrics(value) for key, value in metrics_map.items()
        }

    string_index = getattr(context, "string_index", None)
    if string_index is not None and hasattr(string_index, "is_empty"):
        if not string_index.is_empty():
            summary_payload = _summarise_string_index(string_index)
            basis["string_index"] = {
                "by_origin_type": summary_payload.get("by_origin_type", {}),
                "top_http_hosts": summary_payload.get("top_http_hosts", ()),
                "secret_keyword_hits": summary_payload.get("secret_keyword_hits", 0),
            }

    return basis


def assemble_pipeline_artifacts(
    context: DetectorContext,
) -> PipelineArtifacts:
    """Derive reusable metadata from the pipeline results stored on *context*."""

    results = tuple(getattr(context, "intermediate_results", tuple()))
    trace = build_pipeline_trace(results)
    metrics = collect_detector_metrics(results)
    summary = build_pipeline_summary(results)
    matrices, indicators = build_finding_matrices(results)
    workload = build_workload_profile(results)
    reproducibility_bundle = build_reproducibility_bundle(context)
    extras: dict[str, object] = {}
    if matrices:
        extras["analysis_matrices"] = matrices
    if indicators:
        extras["analysis_indicators"] = indicators
    if workload:
        extras["workload_profile"] = workload
    if extras:
        bundle_copy = dict(reproducibility_bundle)
        bundle_copy.update(extras)
        reproducibility_bundle = bundle_copy
    return PipelineArtifacts(
        results=results,
        trace=trace,
        metrics=metrics,
        summary=summary,
        reproducibility_bundle=reproducibility_bundle,
        matrices=matrices,
        indicators=indicators,
        workload=workload,
    )


def _serialise_metrics(metrics: Mapping[str, object] | None) -> Mapping[str, object]:
    if not metrics:
        return {}

    serialised: dict[str, object] = {}
    for key, value in metrics.items():
        key_text = str(key)
        serialised[key_text] = _serialise_metric_value(value)
    return serialised


def _serialise_metric_value(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {
            str(k): _serialise_metric_value(v)
            for k, v in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [str(item) for item in value]
    return str(value)


def _first_non_empty(*values: object | None) -> str | None:
    for value in values:
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
    return None


def _summarise_string_index(string_index) -> Mapping[str, object]:
    """Return a compact summary of collected strings."""

    origin_counts = string_index.counts_by_origin_type()
    host_counter: Counter[str] = Counter()
    origin_counter: Counter[str] = Counter()
    secret_like = 0
    sample_hashes: list[str] = []

    for entry in getattr(string_index, "strings", tuple()):
        if entry.origin:
            origin_counter[entry.origin] += 1
        value = (entry.value or "").strip()
        if value.lower().startswith(("http://", "https://")):
            try:
                parsed = urlsplit(value)
            except ValueError:
                continue
            host = parsed.netloc.lower()
            if host:
                host_counter[host] += 1
        if any(token in value.lower() for token in ("api_key", "secret", "token", "authorization")):
            secret_like += 1
        if len(sample_hashes) < 10:
            sample_hashes.append(entry.sha256[:12])

    return {
        "total_strings": len(string_index),
        "by_origin_type": origin_counts,
        "top_http_hosts": host_counter.most_common(10),
        "top_origins": origin_counter.most_common(5),
        "secret_keyword_hits": secret_like,
        "sample_hashes": sample_hashes,
    }


__all__ = [
    "PipelineArtifacts",
    "assemble_pipeline_artifacts",
    "build_pipeline_summary",
    "build_pipeline_trace",
    "build_reproducibility_bundle",
    "build_diff_basis",
    "collect_detector_metrics",
]
