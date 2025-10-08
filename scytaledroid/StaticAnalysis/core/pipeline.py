"""Core helpers for running static analysis on APK artifacts."""

from __future__ import annotations
"""High-level orchestration entry point for static analysis runs."""

import json

from collections import Counter
from hashlib import sha256
from time import perf_counter
from pathlib import Path
from typing import Mapping, Optional, Sequence
from xml.etree import ElementTree

from androguard.core.apk import APK

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes, normalise_local_path
from scytaledroid.Utils.LoggingUtils.logging_engine import configure_third_party_loggers

from .context import AnalysisConfig, DetectorContext
from .errors import StaticAnalysisError
from .findings import Badge, DetectorResult, EvidencePointer, Finding
from .manifest_utils import (
    build_manifest_flags,
    collect_exported_components,
    extract_compile_sdk,
    load_manifest_root,
)
from .models import (
    ComponentSummary,
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
    StaticAnalysisReport,
)
from ..modules import StringIndex, build_string_index
from ..modules.network_security import (
    NetworkSecurityPolicy,
    extract_network_security_policy,
)


def make_detector_result(
    *,
    detector_id: str,
    section_key: str,
    status: Badge,
    started_at: float,
    findings: Sequence[Finding] | None = None,
    metrics: Mapping[str, object] | None = None,
    evidence: Sequence[EvidencePointer] | None = None,
    notes: Sequence[str] | None = None,
    subitems: Sequence[Mapping[str, object]] | None = None,
    raw_debug: Optional[str] = None,
) -> DetectorResult:
    """Build a deterministic :class:`DetectorResult` instance."""

    duration = max(0.0, round(perf_counter() - started_at, 1))
    metrics_payload = dict(metrics or {})
    evidence_payload = tuple(evidence or ())
    notes_payload = tuple(note for note in notes or () if note)
    findings_payload = tuple(findings or ())
    if subitems:
        subitems_payload = tuple(dict(item) for item in subitems)
    else:
        subitems_payload = None

    return DetectorResult(
        detector_id=detector_id,
        section_key=section_key,
        status=status,
        duration_sec=duration,
        metrics=metrics_payload,
        evidence=evidence_payload,
        notes=notes_payload,
        findings=findings_payload,
        subitems=subitems_payload,
        raw_debug=raw_debug,
    )


from .detector_runner import PIPELINE_STAGES, PipelineStage, run_detector_pipeline


def analyze_apk(
    apk_path: Path,
    *,
    metadata: Optional[Mapping[str, object]] = None,
    storage_root: Optional[Path] = None,
    config: Optional[AnalysisConfig] = None,
) -> StaticAnalysisReport:
    """Run lightweight static analysis on *apk_path* and return a report."""

    if not apk_path.exists():
        raise StaticAnalysisError(f"APK not found: {apk_path}")

    analysis_config = config or AnalysisConfig()
    report_metadata: dict[str, object] = dict(metadata or {})

    hashes = compute_hashes(apk_path)
    apk_sha256 = hashes.get("sha256", "")
    run_id = _derive_run_id(apk_sha256, analysis_config)
    report_metadata.setdefault("run_id", run_id)

    log_path = configure_third_party_loggers(
        verbosity=analysis_config.verbosity,
        run_id=run_id,
        debug_dir=str(Path(app_config.LOGS_DIR).resolve()),
    )
    if log_path is not None:
        report_metadata["androguard_log_path"] = str(log_path)

    try:
        apk = APK(str(apk_path))
    except Exception as exc:
        raise StaticAnalysisError(f"Failed to open APK: {exc}") from exc

    report_metadata.setdefault("toolchain", _resolve_toolchain_versions())

    manifest_root = load_manifest_root(apk)
    flags = build_manifest_flags(manifest_root)
    compile_sdk = extract_compile_sdk(manifest_root)
    manifest = ManifestSummary(
        package_name=apk.get_package(),
        version_name=apk.get_androidversion_name(),
        version_code=apk.get_androidversion_code(),
        min_sdk=apk.get_min_sdk_version(),
        target_sdk=apk.get_target_sdk_version(),
        compile_sdk=compile_sdk,
        app_label=apk.get_app_name(),
        main_activity=apk.get_main_activity(),
    )

    declared_permissions = tuple(sorted(apk.get_permissions()))
    try:
        permission_details = apk.get_details_permissions()
    except KeyError:
        permission_details = {}
    dangerous = _collect_dangerous_permissions(permission_details)
    custom_permissions = tuple(sorted(apk.get_declared_permissions()))

    permissions = PermissionSummary(
        declared=declared_permissions,
        dangerous=dangerous,
        custom=custom_permissions,
    )

    components = ComponentSummary(
        activities=tuple(sorted(apk.get_activities())),
        services=tuple(sorted(apk.get_services())),
        receivers=tuple(sorted(apk.get_receivers())),
        providers=tuple(sorted(apk.get_providers())),
    )
    exported = collect_exported_components(manifest_root)

    features = tuple(sorted(apk.get_features()))
    libraries = tuple(sorted(apk.get_libraries()))
    signatures = tuple(sorted(apk.get_signature_names()))

    relative = _resolve_relative_path(apk_path, storage_root)
    file_size = apk_path.stat().st_size
    network_security_policy = extract_network_security_policy(
        apk,
        manifest_reference=flags.network_security_config,
    )

    string_index = (
        build_string_index(apk) if analysis_config.enable_string_index else None
    )

    context = _build_detector_context(
        apk_path=apk_path,
        apk=apk,
        manifest_root=manifest_root,
        manifest=manifest,
        manifest_flags=flags,
        permissions=permissions,
        components=components,
        exported=exported,
        features=features,
        libraries=libraries,
        signatures=signatures,
        metadata=report_metadata,
        hashes=hashes,
        config=analysis_config,
        string_index=string_index,
        network_security_policy=network_security_policy,
    )

    detector_results = run_detector_pipeline(context)
    pipeline_trace = _build_pipeline_trace(detector_results)
    if pipeline_trace:
        report_metadata["pipeline_trace"] = pipeline_trace
    findings = tuple(
        finding for result in detector_results for finding in result.findings
    )
    detector_metrics = {
        result.detector_id: dict(result.metrics)
        for result in detector_results
        if result.metrics
    }

    repro_bundle = _build_repro_bundle(
        context,
        network_security_policy,
        string_index,
    )
    if repro_bundle:
        report_metadata["repro_bundle"] = repro_bundle

    return StaticAnalysisReport(
        file_path=str(apk_path.resolve()),
        relative_path=relative,
        file_name=apk_path.name,
        file_size=file_size,
        hashes=hashes,
        manifest=manifest,
        manifest_flags=flags,
        permissions=permissions,
        components=components,
        exported_components=exported,
        features=features,
        libraries=libraries,
        signatures=signatures,
        metadata=report_metadata,
        scan_profile=analysis_config.profile,
        analysis_version=analysis_config.analysis_version,
        findings=findings,
        detector_metrics=detector_metrics,
        detector_results=detector_results,
    )


def _derive_run_id(apk_sha256: str, config: AnalysisConfig) -> str:
    """Return a deterministic identifier for debug log artefacts."""

    detector_list = ",".join(sorted(config.enabled_detectors or ()))
    seed = "|".join(
        (
            apk_sha256 or "unknown",
            config.profile,
            config.verbosity,
            config.persistence_mode,
            config.analysis_version,
            detector_list,
        )
    )
    return sha256(seed.encode("utf-8")).hexdigest()[:16]


def _resolve_relative_path(apk_path: Path, storage_root: Optional[Path]) -> Optional[str]:
    if storage_root is None:
        root = Path(app_config.DATA_DIR).resolve()
        apk_resolved = apk_path.resolve()
        if apk_resolved.is_relative_to(root):
            storage_root = root
        else:
            storage_root = None

    if storage_root is None:
        try:
            return normalise_local_path(apk_path)
        except Exception:
            return None

    try:
        return apk_path.resolve().relative_to(storage_root.resolve()).as_posix()
    except ValueError:
        try:
            return normalise_local_path(apk_path)
        except Exception:
            return None


def _collect_dangerous_permissions(
    permission_details: Mapping[str, Sequence[object]]
) -> tuple[str, ...]:
    """Return the subset of permissions marked as dangerous by Androguard."""

    dangerous: set[str] = set()
    for name, detail in permission_details.items():
        if not detail:
            continue
        protection_level = detail[0]
        if not isinstance(protection_level, str):
            continue
        if "dangerous" in protection_level.lower():
            dangerous.add(name)
    return tuple(sorted(dangerous))


def _build_pipeline_trace(
    results: Sequence[DetectorResult],
) -> list[Mapping[str, object]]:
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

    return trace


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


def _build_detector_context(
    *,
    apk_path: Path,
    apk: APK,
    manifest_root: ElementTree.Element,
    manifest: ManifestSummary,
    manifest_flags: ManifestFlags,
    permissions: PermissionSummary,
    components: ComponentSummary,
    exported: ComponentSummary,
    features: Sequence[str],
    libraries: Sequence[str],
    signatures: Sequence[str],
    metadata: Mapping[str, object],
    hashes: Mapping[str, str],
    config: AnalysisConfig,
    string_index: Optional[StringIndex],
    network_security_policy,
) -> DetectorContext:
    return DetectorContext(
        apk_path=apk_path,
        apk=apk,
        manifest_root=manifest_root,
        manifest_summary=manifest,
        manifest_flags=manifest_flags,
        permissions=permissions,
        components=components,
        exported_components=exported,
        features=tuple(features),
        libraries=tuple(libraries),
        signatures=tuple(signatures),
        metadata=metadata,
        hashes=hashes,
        string_index=string_index,
        network_security_policy=network_security_policy,
        config=config,
    )


def _build_repro_bundle(
    context: DetectorContext,
    network_security_policy: NetworkSecurityPolicy,
    string_index: Optional[StringIndex],
) -> Mapping[str, object]:
    bundle: dict[str, object] = {
        "manifest": context.manifest_summary.to_dict(),
        "manifest_flags": context.manifest_flags.to_dict(),
        "permissions": context.permissions.to_dict(),
        "components": context.components.to_dict(),
        "exported_components": context.exported_components.to_dict(),
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

    if network_security_policy and (
        network_security_policy.source_path or network_security_policy.raw_xml_hash
    ):
        bundle["network_security_config"] = network_security_policy.to_dict()

    if string_index is not None and not string_index.is_empty():
        bundle["string_index"] = {
            "total_strings": len(string_index),
            "by_origin_type": string_index.counts_by_origin_type(),
        }

    diff_basis = _build_diff_basis(context)
    bundle["diff_basis"] = diff_basis
    bundle["diff_basis_hash"] = sha256(
        json.dumps(diff_basis, sort_keys=True).encode("utf-8")
    ).hexdigest()

    return bundle


def _build_diff_basis(context: DetectorContext) -> Mapping[str, object]:
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

    metrics_map = {
        result.detector_id: dict(result.metrics)
        for result in context.intermediate_results
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

    return basis


def _resolve_toolchain_versions() -> Mapping[str, str]:
    versions = {"androguard": "—", "aapt2": "—", "apksigner": "—"}
    try:  # pragma: no cover - dependency introspection
        import androguard

        version = getattr(androguard, "__version__", None)
        if isinstance(version, str) and version.strip():
            versions["androguard"] = version
    except Exception:  # pragma: no cover - best-effort metadata
        pass
    return versions


__all__ = [
    "PipelineStage",
    "PIPELINE_STAGES",
    "StaticAnalysisReport",
    "ManifestSummary",
    "ManifestFlags",
    "PermissionSummary",
    "ComponentSummary",
    "StaticAnalysisError",
    "analyze_apk",
    "make_detector_result",
]
