"""High-level static analysis run persistence pipeline."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Database.db_core import db_queries as core_q

from ..cvss_v4 import apply_profiles
from ..evidence import normalize_evidence
from ..masvs_mapper import summarise_controls, rule_to_area
from ..rule_mapping import derive_rule_id
from .metrics_writer import compute_metrics_bundle, write_buckets, write_contributors, write_metrics
from .findings_writer import (
    compute_cvss_base,
    derive_masvs_tag,
    extract_rule_hint,
    persist_findings,
    persist_masvs_controls,
)
from .run_envelope import prepare_run_envelope
from .permission_risk import persist_permission_risk
from .permission_matrix import persist_permission_matrix
from .static_sections import (
    coerce_severity_counts,
    normalise_string_counts,
    persist_static_sections,
    persist_storage_surface_data,
)
from .utils import (
    canonical_severity_counts,
    coerce_mapping,
    first_text,
    normalise_severity_token,
    safe_int,
    truncate,
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


def _persist_static_sections_wrapper(
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
    static_run_id: int | None = None,
) -> Tuple[list[str], bool, int]:
    return persist_static_sections(
        package_name=package_name,
        session_stamp=session_stamp,
        scope_label=scope_label,
        finding_totals=finding_totals,
        baseline_section=baseline_section,
        string_payload=string_payload,
        manifest=manifest,
        app_metadata=app_metadata,
        run_id=run_id,
        static_run_id=static_run_id,
    )


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
    try:
        metadata_map: Mapping[str, object] = getattr(br, "metadata", {}) or {}
    except Exception:
        metadata_map = {}
    manifest_obj = getattr(br, "manifest", None)
    package_for_run = getattr(manifest_obj, "package_name", None) or run_package

    if dry_run:
        log.info(
            f"Dry-run enabled; persistence for {run_package} will be simulated",
            category="static_analysis",
        )

    if not session_stamp and metadata_map:
        value = metadata_map.get("session_stamp")
        if isinstance(value, str) and value.strip():
            session_stamp = value.strip()

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
    static_run_id: int | None = None
    try:
        # Prefer an existing static_analysis_runs entry for this session/package
        row = core_q.run_sql(
            """
            SELECT sar.id
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.session_stamp = %s
              AND a.package_name = %s
            ORDER BY sar.id DESC
            LIMIT 1
            """,
            (session_stamp, package_for_run),
            fetch="one",
        )
        if row and row[0]:
            static_run_id = int(row[0])
    except Exception:
        static_run_id = None

    def _create_static_run(app_version_id: int) -> int | None:
        try:
            run_id = core_q.run_sql(
                """
                INSERT INTO static_analysis_runs (
                    app_version_id, session_stamp, scope_label, profile, findings_total
                ) VALUES (%s,%s,%s,%s,%s)
                """,
                (
                    app_version_id,
                    session_stamp,
                    scope_label,
                    "Full",
                    int(finding_totals.get("total", 0) or 0),
                ),
                return_lastrowid=True,
            )
            return int(run_id) if run_id else None
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                f"Failed to create static_analysis_runs row for {package_for_run}: {exc}",
                category="db",
            )
            return None

    def _ensure_app_version() -> int | None:
        """Fetch or create an app_version so static_run_id can be keyed reliably."""
        display_name = getattr(manifest_obj, "app_label", None) or package_for_run
        version_code = None
        version_name = getattr(manifest_obj, "version_name", None) if manifest_obj else None
        min_sdk = safe_int(getattr(manifest_obj, "min_sdk", None) or getattr(manifest_obj, "min_sdk_version", None))
        target_sdk = safe_int(getattr(manifest_obj, "target_sdk", None))
        try:
            version_code = safe_int(getattr(manifest_obj, "version_code", None)) if manifest_obj else None
        except Exception:
            version_code = None

        try:
            app_id = None
            row = core_q.run_sql(
                "SELECT id FROM apps WHERE package_name=%s",
                (package_for_run,),
                fetch="one",
            )
            if row and row[0]:
                app_id = int(row[0])
            else:
                app_id = core_q.run_sql(
                    "INSERT INTO apps (package_name, display_name) VALUES (%s,%s)",
                    (package_for_run, display_name),
                    return_lastrowid=True,
                )
                app_id = int(app_id) if app_id else None
            if app_id is None:
                return None

            params = (app_id, version_name, version_code)
            row = core_q.run_sql(
                """
                SELECT id FROM app_versions
                WHERE app_id=%s AND version_name<=>%s AND version_code<=>%s
                ORDER BY id DESC LIMIT 1
                """,
                params,
                fetch="one",
            )
            if row and row[0]:
                return int(row[0])

            av_id = core_q.run_sql(
                """
                INSERT INTO app_versions (app_id, version_name, version_code, min_sdk, target_sdk)
                VALUES (%s,%s,%s,%s,%s)
                """,
                (app_id, version_name, version_code, min_sdk, target_sdk),
                return_lastrowid=True,
            )
            return int(av_id) if av_id else None
        except Exception as exc:  # pragma: no cover - defensive
            log.warning(
                f"Failed to resolve/create app_version for {package_for_run}: {exc}",
                category="static_analysis",
            )
            return None

    if static_run_id is None and not dry_run:
        # Attempt to create a static_analysis_runs row so downstream tables can
        # be keyed by static_run_id even on fresh schemas.
        app_version_id = _ensure_app_version()
        if app_version_id is not None:
            static_run_id = _create_static_run(app_version_id)
            if static_run_id:
                log.info(
                    f"Resolved static_run_id={static_run_id} for {package_for_run} (session={session_stamp})",
                    category="static_analysis",
                )
        else:
            log.warning(
                (
                    f"Could not resolve app_version_id for {package_for_run}; "
                    f"static_run_id will remain unset and persistence will be legacy-only."
                ),
                category="static_analysis",
            )

    metrics_bundle = compute_metrics_bundle(br, string_data)
    code_http_hosts = metrics_bundle.code_http_hosts
    asset_http_hosts = metrics_bundle.asset_http_hosts

    if run_id is not None:
        if not write_buckets(int(run_id), metrics_bundle.buckets, static_run_id=static_run_id):
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
                detector_sev = normalise_severity_token(getattr(f, "severity", None))
                if detector_sev is None:
                    detector_sev = normalise_severity_token(getattr(f, "severity_label", None))
                metrics_map = getattr(f, "metrics", None)
                if isinstance(metrics_map, Mapping):
                    detector_sev = detector_sev or normalise_severity_token(
                        metrics_map.get("severity")
                    )
                    detector_sev = detector_sev or normalise_severity_token(
                        metrics_map.get("severity_level")
                    )
                gate_value = getattr(getattr(f, "severity_gate", None), "value", None)
                gate_sev = normalise_severity_token(gate_value)
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
                        "cvss": truncate(base_vector, 128),
                        "kind": detector_id,
                        "module_id": module_id,
                        "evidence": truncate(evidence_payload, 512),
                        "evidence_path": truncate(evidence_path, 512),
                        "evidence_offset": truncate(evidence_offset, 64),
                        "evidence_preview": truncate(evidence_preview, 256),
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
        severity_counts = canonical_severity_counts(severity_counter)
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
        elif not persist_findings(int(run_id), finding_rows, static_run_id=static_run_id):
            message = (
                f"Failed to persist findings for run_id={run_id} "
                f"static_run_id={static_run_id}"
            )
            log.warning(message, category="static_analysis")
            outcome.add_error(message)

    if run_id is not None:
        if control_summary:
            persist_masvs_controls(
                int(run_id),
                package_for_run,
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
        persist_storage_surface_data(br, session_stamp, scope_label)
        apk_identifier = safe_int(metadata_map.get("apk_id")) if metadata_map else None
        if apk_identifier is None and metadata_map:
            apk_identifier = safe_int(metadata_map.get("apkId"))
        if apk_identifier is None:
            apk_identifier = safe_int(metadata_map.get("android_apk_id"))
        if apk_identifier is None:
            apk_identifier = int(run_id)

        permission_profiles_map: Mapping[str, Mapping[str, object]] | None = None
        detector_metrics = getattr(br, "detector_metrics", None)
        if isinstance(detector_metrics, Mapping):
            permission_metrics = detector_metrics.get("permissions_profile")
            if isinstance(permission_metrics, Mapping):
                profiles = permission_metrics.get("permission_profiles")
                if isinstance(profiles, Mapping):
                    permission_profiles_map = profiles

        persist_permission_matrix(
            run_id=int(run_id),
            package_name=package_for_run,
            apk_id=apk_identifier,
            permission_profiles=permission_profiles_map,
        )
        persist_permission_risk(
            run_id=int(run_id),
            report=br,
            package_name=package_for_run,
            session_stamp=session_stamp,
            scope_label=scope_label,
            metrics_bundle=metrics_bundle,
            baseline_payload=baseline_payload,
        )

    perm_detail_map: Mapping[str, object] = (
        metrics_bundle.permission_detail
        if isinstance(metrics_bundle.permission_detail, Mapping)
        else {}
    )
    flagged_normal_metric = float(perm_detail_map.get("flagged_normal_count", 0) or 0)
    weak_guard_metric = float(perm_detail_map.get("weak_guard_count", 0) or 0)

    metrics_payload = {
        "network.code_http_hosts": (float(code_http_hosts), None),
        "network.asset_http_hosts": (float(asset_http_hosts), None),
        "exports.total": (float(getattr(getattr(br, "exported_components", None), "total", lambda: 0)()), None),
        "permissions.dangerous_count": (float(getattr(metrics_bundle, "dangerous_permissions", 0)), None),
        "permissions.signature_count": (float(getattr(metrics_bundle, "signature_permissions", 0)), None),
        "permissions.vendor_count": (float(getattr(metrics_bundle, "vendor_permissions", 0)), None),
        "permissions.flagged_normal_count": (flagged_normal_metric, None),
        "permissions.weak_guard_count": (weak_guard_metric, None),
        "permissions.risk_score": (float(getattr(metrics_bundle, "permission_score", 0.0)), None),
        "permissions.risk_grade": (None, getattr(metrics_bundle, "permission_grade", "")),
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

    if run_id is not None and not write_metrics(int(run_id), metrics_payload, static_run_id=static_run_id):
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
        static_errors, baseline_written, sample_total = _persist_static_sections_wrapper(
            package_name=package_for_run,
            session_stamp=session_stamp,
            scope_label=scope_label,
            finding_totals=persisted_totals,
            baseline_section=baseline_section if isinstance(baseline_section, Mapping) else {},
            string_payload=string_payload if isinstance(string_payload, Mapping) else {},
            manifest=br.manifest,
            app_metadata=baseline_payload.get("app") if isinstance(baseline_payload, Mapping) else {},
            run_id=run_id,
            static_run_id=static_run_id,
        )
        if baseline_written:
            outcome.baseline_written = True
        outcome.string_samples_persisted = sample_total
        for err in static_errors:
            outcome.add_error(err)

    return outcome


__all__ = ["persist_run_summary", "PersistenceOutcome"]
