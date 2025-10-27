"""High-level run persistence helpers (buckets, metrics, findings, contributors)."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .cvss_v4 import apply_profiles
from .evidence import normalize_evidence
from .masvs_mapper import summarise_controls, rule_to_area
from .rule_mapping import derive_rule_id
from .persistence import (
    coerce_severity_counts,
    compute_cvss_base,
    compute_metrics_bundle,
    derive_masvs_tag,
    extract_rule_hint,
    normalise_string_counts,
    persist_findings,
    persist_masvs_controls,
    persist_static_findings,
    persist_string_summary,
    prepare_run_envelope,
    write_buckets,
    write_contributors,
    write_metrics,
)


@dataclass(slots=True)
class PersistenceOutcome:
    run_id: int | None = None
    runtime_findings: int = 0
    persisted_findings: int = 0
    baseline_written: bool = False
    string_samples_persisted: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.errors

    def add_error(self, message: str) -> None:
        self.errors.append(message)


def _truncate(value: Optional[str], limit: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        inner = text[1:-1].strip()
        if inner:
            text = inner
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _coerce_mapping(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in vars(obj).items() if not k.startswith("_")}
    if hasattr(obj, "__slots__"):
        data: Dict[str, Any] = {}
        for attr in getattr(obj, "__slots__", ()):  # type: ignore[attr-defined]
            if attr.startswith("_"):
                continue
            try:
                value = getattr(obj, attr)
            except Exception:  # pragma: no cover - defensive
                continue
            if callable(value):
                continue
            data[attr] = value
        return data
    data: Dict[str, Any] = {}
    for attr in dir(obj):
        if attr.startswith("_"):
            continue
        try:
            value = getattr(obj, attr)
        except Exception:  # pragma: no cover - defensive
            continue
        if callable(value):
            continue
        data[attr] = value
    return data


_SEVERITY_CANONICAL = {
    "critical": "High",
    "high": "High",
    "p0": "High",
    "medium": "Medium",
    "med": "Medium",
    "p1": "Medium",
    "low": "Low",
    "p2": "Low",
    "info": "Info",
    "information": "Info",
    "note": "Info",
    "p3": "Low",
    "p4": "Info",
}


def _normalise_severity_token(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    mapped = _SEVERITY_CANONICAL.get(text)
    if mapped:
        return mapped
    if text and text[0] in _SEVERITY_CANONICAL:
        return _SEVERITY_CANONICAL.get(text[0])
    return None


def _canonical_severity_counts(counter: Counter[str]) -> Dict[str, int]:
    return {
        "High": int(counter.get("High", 0)),
        "Medium": int(counter.get("Medium", 0)),
        "Low": int(counter.get("Low", 0)),
        "Info": int(counter.get("Info", 0)),
    }


def _persist_storage_surface_data(report, session_stamp: str, scope_label: str) -> None:
    try:
        from scytaledroid.StaticAnalysis.modules.storage_surface import (
            AppModuleContext,
            StorageSurfaceModule,
        )
    except Exception:
        return

    apk_path = getattr(report, "file_path", None)
    package_name = getattr(report.manifest, "package_name", None) or report.metadata.get("package")
    if not apk_path or not package_name:
        return

    metadata = dict(report.metadata or {})
    context = AppModuleContext(
        report=report,
        package_name=str(package_name),
        apk_path=Path(apk_path),
        metadata=metadata,
        session_stamp=session_stamp,
        scope_label=scope_label,
    )

    module = StorageSurfaceModule()
    try:
        module_result = module.run(context)
        module.persist(module_result)
    except Exception:
        return


def _persist_static_sections(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_section: Mapping[str, object],
    string_payload: Mapping[str, object],
    manifest: object | None,
    app_metadata: Mapping[str, object] | object,
    run_id: int | None,
) -> tuple[list[str], bool, int]:
    errors: list[str] = []
    baseline_written = False
    metadata_map: Mapping[str, object] = (
        dict(app_metadata)
        if isinstance(app_metadata, Mapping)
        else {}
    )

    def _first_text(*values: object | None) -> str | None:
        for value in values:
            if value is None:
                continue
            try:
                text = str(value).strip()
            except Exception:
                continue
            if text:
                return text
        return None

    def _maybe_int(value: object | None) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    manifest_obj = manifest
    app_label = _first_text(
        getattr(manifest_obj, "app_label", None) if manifest_obj else None,
        metadata_map.get("label"),
        metadata_map.get("app_label"),
        metadata_map.get("display_name"),
    ) or package_name
    version_name = _first_text(
        getattr(manifest_obj, "version_name", None) if manifest_obj else None,
        metadata_map.get("version_name"),
    )
    version_code = _maybe_int(
        getattr(manifest_obj, "version_code", None) if manifest_obj else None
        or metadata_map.get("version_code")
    )
    target_sdk = _maybe_int(
        getattr(manifest_obj, "target_sdk", None) if manifest_obj else None
        or metadata_map.get("target_sdk")
    )
    min_sdk = _maybe_int(
        getattr(manifest_obj, "min_sdk", None) if manifest_obj else None
        or metadata_map.get("min_sdk")
    )

    severity_counts = coerce_severity_counts(finding_totals)
    details = {
        "manifest_flags": baseline_section.get("manifest_flags"),
        "exports": baseline_section.get("exports"),
        "permissions": baseline_section.get("permissions"),
        "nsc": baseline_section.get("nsc"),
        "string_counts": (
            string_payload.get("counts")
            if isinstance(string_payload.get("counts"), Mapping)
            else {}
        ),
        "app": {
            "label": app_label,
            "package": package_name,
            "session_stamp": session_stamp,
            "scope_label": scope_label,
            **(
                {
                    key: value
                    for key, value in {
                        "version_name": version_name,
                        "version_code": version_code,
                        "target_sdk": target_sdk,
                        "min_sdk": min_sdk,
                    }.items()
                    if value not in (None, "")
                }
            ),
        },
    }

    findings = baseline_section.get("findings")
    findings_seq: Sequence[object] | None = findings if isinstance(findings, Sequence) else None
    baseline_errors = persist_static_findings(
        package_name=package_name,
        session_stamp=session_stamp,
        scope_label=scope_label,
        severity_counts=severity_counts,
        details=details,
        findings=findings_seq,
    )
    if baseline_errors:
        errors.extend(baseline_errors)
    else:
        baseline_written = True

    counts = normalise_string_counts(string_payload.get("counts"))
    samples_payload = string_payload.get("samples")
    samples = samples_payload if isinstance(samples_payload, Mapping) else {}
    sample_total = 0
    for values in samples.values():
        if isinstance(values, Sequence):
            sample_total += len(values)
    string_errors = persist_string_summary(
        package_name=package_name,
        session_stamp=session_stamp,
        scope_label=scope_label,
        counts=counts,
        samples=samples,
        run_id=run_id,
    )
    if string_errors:
        errors.extend(string_errors)
        sample_total = 0

    return errors, baseline_written, sample_total


def persist_run_summary(
    base_report,
    string_data: Mapping[str, object],
    run_package: str,
    *,
    session_stamp: str | None,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_payload: Mapping[str, object],
    dry_run: bool = False,
) -> PersistenceOutcome:
    outcome = PersistenceOutcome()
    br = base_report
    if dry_run:
        log.info(
            f"Dry-run enabled; persistence for {run_package} will be simulated",
            category="static_analysis",
        )

    if not session_stamp:
        try:
            meta = getattr(br, "metadata", {}) or {}
            value = meta.get("session_stamp")
            if isinstance(value, str) and value.strip():
                session_stamp = value.strip()
        except Exception:
            pass

    if not session_stamp:
        message = f"Missing session stamp for {run_package}; static persistence will be skipped."
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        return outcome

    envelope, envelope_errors = prepare_run_envelope(
        report=br,
        baseline_payload=baseline_payload,
        run_package=run_package,
        session_stamp=session_stamp,
        dry_run=dry_run,
    )
    for err in envelope_errors:
        outcome.add_error(err)
    run_id = envelope.run_id
    if run_id:
        outcome.run_id = run_id

    metrics_bundle = compute_metrics_bundle(br, string_data)
    code_http_hosts = metrics_bundle.code_http_hosts
    asset_http_hosts = metrics_bundle.asset_http_hosts

    if run_id is not None:
        if not write_buckets(int(run_id), metrics_bundle.buckets):
            message = f"Failed to persist scoring buckets for run_id={run_id}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)

    baseline_counts = coerce_severity_counts(finding_totals)
    severity_counter: Counter[str] = Counter()
    downgraded_high = 0

    finding_rows: list[Dict[str, Any]] = []
    control_entries: list[Tuple[str, Mapping[str, Any]]] = []
    total_findings = 0
    rule_assigned = 0
    base_vector_count = 0
    bte_vector_count = 0
    preview_assigned = 0
    path_assigned = 0

    try:
        for result in (br.detector_results or ()):  # type: ignore[attr-defined]
            detector_id = str(getattr(result, "detector_id", getattr(result, "section_key", None)) or "unknown")
            module_id_val = getattr(result, "module_id", None)
            module_id = str(module_id_val) if module_id_val not in (None, "") else None
            for f in result.findings:
                total_findings += 1
                detector_sev = _normalise_severity_token(getattr(f, "severity", None))
                if detector_sev is None:
                    detector_sev = _normalise_severity_token(getattr(f, "severity_label", None))
                metrics_map = getattr(f, "metrics", None)
                if isinstance(metrics_map, Mapping):
                    detector_sev = detector_sev or _normalise_severity_token(
                        metrics_map.get("severity")
                    )
                    detector_sev = detector_sev or _normalise_severity_token(
                        metrics_map.get("severity_level")
                    )
                gate_value = getattr(getattr(f, "severity_gate", None), "value", None)
                gate_sev = _normalise_severity_token(gate_value)
                sev = detector_sev or gate_sev or "Info"
                if detector_sev == "High" and sev != "High":
                    downgraded_high += 1
                severity_counter[sev] += 1
                evidence = normalize_evidence(
                    f.evidence,
                    detail_hint=getattr(f, "detail", None)
                    or getattr(f, "headline", None)
                    or getattr(f, "summary", None)
                    or getattr(f, "because", None),
                    path_hint=getattr(f, "path", None),
                    offset_hint=getattr(f, "offset", None),
                )
                evidence_payload = json.dumps(evidence.as_payload(), ensure_ascii=False)
                evidence_path = evidence.path
                evidence_offset = evidence.offset
                evidence_preview = evidence.detail
                if evidence_preview:
                    preview_assigned += 1
                if evidence_path:
                    path_assigned += 1
                rule_id = derive_rule_id(
                    detector_id,
                    module_id,
                    evidence_path,
                    evidence_preview,
                    rule_id_hint=extract_rule_hint(f),
                )
                if rule_id:
                    rule_assigned += 1
                masvs_area = derive_masvs_tag(f, rule_id, lookup_rule_area=rule_to_area)
                base_vector, base_score, base_meta = compute_cvss_base(rule_id)
                if base_vector:
                    base_vector_count += 1
                (
                    bt_vector,
                    bt_score,
                    be_vector,
                    be_score,
                    bte_vector,
                    bte_score,
                    profile_meta,
                ) = apply_profiles(base_vector, envelope.threat_profile, envelope.env_profile)
                if bte_vector:
                    bte_vector_count += 1
                meta_combined: Dict[str, Any] = {}
                if base_meta:
                    meta_combined.update(base_meta)
                if profile_meta:
                    meta_combined.update(profile_meta)
                finding_rows.append(
                    {
                        "severity": sev,
                        "masvs": masvs_area,
                        "cvss": _truncate(base_vector, 128),
                        "kind": detector_id,
                        "module_id": module_id,
                        "evidence": _truncate(evidence_payload, 512),
                        "evidence_path": _truncate(evidence_path, 512),
                        "evidence_offset": _truncate(evidence_offset, 64),
                        "evidence_preview": _truncate(evidence_preview, 256),
                        "rule_id": rule_id,
                        "cvss_v40_b_vector": base_vector,
                        "cvss_v40_b_score": base_score,
                        "cvss_v40_bt_vector": bt_vector,
                        "cvss_v40_bt_score": bt_score,
                        "cvss_v40_be_vector": be_vector,
                        "cvss_v40_be_score": be_score,
                        "cvss_v40_bte_vector": bte_vector,
                        "cvss_v40_bte_score": bte_score,
                        "cvss_v40_meta": json.dumps(meta_combined, ensure_ascii=False) if meta_combined else None,
                    }
                )
                control_entries.extend(getattr(result, "masvs_coverage", []))
    except Exception as exc:
        message = f"Failed to coerce findings for {run_package}: {exc}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    control_summary = summarise_controls(control_entries)
    outcome.runtime_findings = int(total_findings)
    outcome.persisted_findings = len(finding_rows)

    if severity_counter:
        severity_counts = _canonical_severity_counts(severity_counter)
        persisted_totals = Counter(severity_counts)
        mismatch = {
            key: severity_counts[key] - baseline_counts.get(key, 0)
            for key in severity_counts
            if severity_counts[key] != baseline_counts.get(key, 0)
        }
        if mismatch:
            log.info(
                f"Adjusted severity totals for {run_package} based on detector output: {mismatch}",
                category="static_analysis",
            )
    else:
        severity_counts = baseline_counts
        persisted_totals = Counter(severity_counts)

    if finding_rows:
        if run_id is None:
            sample = finding_rows[0] if finding_rows else {}
            sample_view = {
                key: sample.get(key)
                for key in ("rule_id", "evidence_path", "evidence_preview", "severity")
            }
            log.info(
                (
                    f"Dry-run persistence payload for {run_package}: "
                    f"findings={total_findings} "
                    f"sample={json.dumps(sample_view, ensure_ascii=False)}"
                ),
                category="static_analysis",
            )
        elif not persist_findings(int(run_id), finding_rows):
            message = f"Failed to persist findings for run_id={run_id}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)

    if run_id is not None:
        if control_summary:
            persist_masvs_controls(
                int(run_id),
                br.manifest.package_name or run_package,
                control_summary,
            )
        else:
            log.info(
                (
                    f"No MASVS control coverage derived for {run_package}; "
                    f"total_findings={total_findings} entries={len(control_entries)}"
                ),
                category="static_analysis",
            )
        _persist_storage_surface_data(br, session_stamp, scope_label)

    metrics_payload = {
        "network.code_http_hosts": (float(code_http_hosts), None),
        "network.asset_http_hosts": (float(asset_http_hosts), None),
        "exports.total": (float(getattr(getattr(br, "exported_components", None), "total", lambda: 0)()), None),
    }
    metrics_payload["findings.total"] = (float(total_findings), None)
    if downgraded_high:
        metrics_payload["findings.high_downgraded"] = (float(downgraded_high), None)
    rule_cov_pct = (float(rule_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    base_cov_pct = (float(base_vector_count) / float(total_findings) * 100.0) if total_findings else 0.0
    bte_cov_pct = (float(bte_vector_count) / float(total_findings) * 100.0) if total_findings else 0.0
    preview_cov_pct = (float(preview_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    path_cov_pct = (float(path_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    metrics_payload["findings.ruleid_coverage_pct"] = (rule_cov_pct, None)
    metrics_payload["findings.preview_coverage_pct"] = (preview_cov_pct, None)
    metrics_payload["findings.path_coverage_pct"] = (path_cov_pct, None)
    metrics_payload["cvss.base_vector_coverage_pct"] = (base_cov_pct, None)
    metrics_payload["cvss.bte_vector_coverage_pct"] = (bte_cov_pct, None)

    if run_id is not None and not write_metrics(int(run_id), metrics_payload):
        message = f"Failed to persist metrics for run_id={run_id}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    summary_run_id = run_id if run_id is not None else "dry-run"
    log.info(
        (
            f"Persistence summary for {run_package} (run_id={summary_run_id}): "
            f"findings={total_findings} "
            f"rule_id={rule_cov_pct:.1f}% "
            f"preview={preview_cov_pct:.1f}% "
            f"path={path_cov_pct:.1f}% "
            f"bte={bte_cov_pct:.1f}%"
        ),
        category="static_analysis",
    )

    contributors = metrics_bundle.contributors
    if contributors and run_id is not None:
        if not write_contributors(int(run_id), contributors):
            message = f"Failed to persist contributor breakdown for run_id={run_id}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)

    if run_id is not None:
        baseline_section = baseline_payload.get("baseline") if isinstance(baseline_payload, Mapping) else {}
        string_payload = baseline_section.get("string_analysis") if isinstance(baseline_section, Mapping) else {}
        static_errors, baseline_written, sample_total = _persist_static_sections(
            package_name=br.manifest.package_name or run_package,
            session_stamp=session_stamp,
            scope_label=scope_label,
            finding_totals=persisted_totals,
            baseline_section=baseline_section if isinstance(baseline_section, Mapping) else {},
            string_payload=string_payload if isinstance(string_payload, Mapping) else {},
            manifest=br.manifest,
            app_metadata=baseline_payload.get("app") if isinstance(baseline_payload, Mapping) else {},
            run_id=run_id,
        )
        if baseline_written:
            outcome.baseline_written = True
        outcome.string_samples_persisted = sample_total
        for err in static_errors:
            outcome.add_error(err)

    return outcome


__all__ = ["persist_run_summary", "PersistenceOutcome"]
