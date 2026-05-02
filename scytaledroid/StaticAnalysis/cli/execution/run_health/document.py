"""Build the ``run_health.json`` document payload."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from ...core.models import RunOutcome, RunParameters, ScopeSelection
from .governance import (
    _session_db_persistence_label,
    _session_detector_pipeline_status,
    infer_session_governance_snapshot,
)
from .projection import _web_session_health_projection_for_app, collect_report_paths_for_app
from .rollup import rollup_parse_fallback_signals
from .signals import string_summary_signals, summarize_execution_signals_for_app
from .status import compute_run_aggregate_status


def build_run_health_document(
    outcome: RunOutcome,
    params: RunParameters,
    *,
    persistence_enabled: bool,
    persist_attempted: bool,
) -> dict[str, object]:
    from ..scan_report import _summarize_app_pipeline

    selection: ScopeSelection = outcome.scope

    detector_errors_total = 0
    detector_warnings_total = 0
    detector_failures_total = 0
    parse_fallback_total = 0
    findings_runtime_total = 0
    findings_persisted_total = 0
    findings_capped_total_sum = 0
    string_warn_apps = 0
    partial_ct = completed_ct = failed_ct = skipped_ct = 0
    artifact_rows_total = outcome.total_artifacts
    scanned_success = outcome.completed_artifacts

    apps_out: list[dict[str, object]] = []
    for app in outcome.results:
        summary = _summarize_app_pipeline(app)
        rollup = rollup_parse_fallback_signals(app)

        errs = int(summary.get("error_count", 0) or 0)
        detector_errors_total += errs
        detector_warnings_total += int(summary.get("warn_count", 0) or 0)
        detector_failures_total += int(summary.get("fail_count", 0) or 0)

        pf_est = int(rollup.get("parse_fallback_events_est", 0) or 0)
        parse_fallback_total += pf_est

        str_sig = string_summary_signals(
            getattr(app, "base_string_data", None),
            discovered_artifacts=int(getattr(app, "discovered_artifacts", 0) or 0),
        )
        if str(str_sig.get("string_summary_status") or "ok") != "ok":
            string_warn_apps += 1

        st = getattr(app, "final_status", None) or ""
        if st == "complete":
            completed_ct += 1
        elif st == "partial":
            partial_ct += 1
        elif st == "skipped":
            skipped_ct += 1
        elif st == "failed":
            failed_ct += 1

        persisted = bool(params.persistence_ready and persistence_enabled)
        persisted_ok_app = persisted and bool(getattr(app, "persisted_artifacts", 0)) and not bool(
            getattr(app, "persistence_failure_stage", None) or getattr(app, "persistence_exception_class", None)
        )
        rt_pf = getattr(app, "persistence_runtime_findings", None)
        ps_pf = getattr(app, "persistence_persisted_findings", None)
        cap_pf = getattr(app, "persistence_findings_capped_total", None)
        if isinstance(rt_pf, int):
            findings_runtime_total += rt_pf
        if isinstance(ps_pf, int):
            findings_persisted_total += ps_pf
        if isinstance(cap_pf, int):
            findings_capped_total_sum += cap_pf

        capped_map = getattr(app, "persistence_findings_capped_by_detector", None)
        capped_serial: dict[str, int] = {}
        if isinstance(capped_map, Mapping):
            for k, v in capped_map.items():
                try:
                    capped_serial[str(k)] = int(v)
                except (TypeError, ValueError):
                    continue

        web_projection = _web_session_health_projection_for_app(
            app,
            persistence_enabled=persisted,
            persist_attempted=persist_attempted,
            persisted=persisted,
            persisted_ok_app=persisted_ok_app,
            rt_pf=rt_pf,
            ps_pf=ps_pf,
            cap_pf=cap_pf,
        )

        exec_signals = summarize_execution_signals_for_app(
            app,
            persistence_enabled=persisted,
            persist_attempted=persist_attempted,
        )

        apps_out.append(
            {
                "package_name": app.package_name,
                "app_label": getattr(app, "app_label", None),
                "category": getattr(app, "category", None),
                "final_status": getattr(app, "final_status", None),
                "discovered_artifacts": int(getattr(app, "discovered_artifacts", 0) or 0),
                "artifacts_scanned_ok": len(getattr(app, "artifacts", []) or ()),
                "artifacts_failed": int(getattr(app, "failed_artifacts", 0) or 0),
                "executed_artifact_attempts": int(getattr(app, "executed_artifacts", 0) or 0),
                "detector_executed_agg": summary.get("detector_executed"),
                "detector_skipped_agg": summary.get("detector_skipped"),
                "detector_total_agg": summary.get("detector_total"),
                "detector_errors_agg": errs,
                "skipped_detectors_merged": summary.get("skipped_detectors") or [],
                "parse_fallback_signals": rollup,
                "string_summary": str_sig,
                "report_saved": bool(collect_report_paths_for_app(app)),
                "report_paths_short": collect_report_paths_for_app(app, limit=16),
                "db_persistence_enabled": persisted,
                "db_persisted_ok": persisted_ok_app,
                "static_run_id": getattr(app, "static_run_id", None),
                "finding_persistence": {
                    "runtime_findings": rt_pf if isinstance(rt_pf, int) else None,
                    "persisted_findings_db": ps_pf if isinstance(ps_pf, int) else None,
                    "capped_not_persisted": cap_pf if isinstance(cap_pf, int) else None,
                    "capped_by_detector": capped_serial if capped_serial else {},
                },
                "mysql_web_session_health_projection": web_projection,
                "execution_signals": exec_signals,
            }
        )

    run_aggregate = getattr(outcome, "run_aggregate_status", None) or compute_run_aggregate_status(outcome)

    tot = int(artifact_rows_total or 0)
    done = int(scanned_success or 0)
    if tot <= 0:
        # Degenerate / harness outcomes may omit artifact counters; treat as complete when not aborted.
        scan_execution_complete = not outcome.aborted
    else:
        scan_execution_complete = bool(not outcome.aborted and done >= tot)

    preset = getattr(params, "profile", None)

    paths_sample: list[str] = []
    for app in outcome.results:
        paths_sample.extend(collect_report_paths_for_app(app, limit=4))
        if len(paths_sample) >= 12:
            paths_sample = paths_sample[:12]
            break

    session_stamp = getattr(params, "session_stamp", None)

    db_persistence_status = _session_db_persistence_label(
        outcome,
        persistence_enabled=persistence_enabled,
        persist_attempted=persist_attempted,
        params=params,
    )
    detector_pipeline_status = _session_detector_pipeline_status(
        detector_errors_total,
        detector_warnings_total,
        detector_failures_total,
    )
    string_session_status = "warnings" if string_warn_apps > 0 else "ok"
    governance_snapshot = infer_session_governance_snapshot(params)

    payload: dict[str, object] = {
        "schema_version": 3,
        "generated_at_utc": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "session_stamp": session_stamp,
        "session_label": getattr(params, "session_label", None) or session_stamp,
        "preset": str(preset) if preset else None,
        "preset_label": getattr(params, "profile_label", None),
        "scope_kind": getattr(selection, "scope", None),
        "scope_profile_label": getattr(selection, "label", None),
        "final_run_status": run_aggregate,
        "aborted": bool(outcome.aborted),
        "persistence_requested": persistence_enabled,
        "persistence_ready_param": bool(getattr(params, "persistence_ready", False)),
        "outcome_persistence_failed": bool(outcome.persistence_failed),
        "apps": apps_out,
        "governance": governance_snapshot,
        "status_reasons": {
            "detector_warnings": detector_warnings_total,
            "detector_failures": detector_failures_total,
            "detector_errors": detector_errors_total,
            # Explicit names for operators (same counts as detector_errors / detector_failures).
            "detector_execution_errors": detector_errors_total,
            "detector_finding_failures": detector_failures_total,
            "parse_fallbacks": parse_fallback_total,
            "string_status": string_session_status,
            "db_persistence_status": db_persistence_status,
            "detector_pipeline_status": detector_pipeline_status,
            # Deprecated alias: historically named "status" but mixed policy-fail stages with execution errors.
            "detector_status": detector_pipeline_status,
            "governance_grade": governance_snapshot.get("governance_grade"),
            "governance_reason": governance_snapshot.get("governance_reason"),
        },
        "run_rollups": {
            "app_total": len(outcome.results),
            "artifact_total_discovered_estimate": artifact_rows_total,
            "artifacts_scan_completed_counter": scanned_success,
            "apps_complete_final": completed_ct,
            "apps_partial_final": partial_ct,
            "apps_failed_final": failed_ct,
            "apps_skipped_final": skipped_ct,
            "detector_errors_total_estimate": detector_errors_total,
            "detector_warnings_total_estimate": detector_warnings_total,
            "detector_failures_total_estimate": detector_failures_total,
            "parse_fallback_events_total_estimate": parse_fallback_total,
            "string_summary_warning_apps_estimate": string_warn_apps,
            "persist_attempted_this_run": persist_attempted,
            "findings_runtime_total": findings_runtime_total,
            "findings_persisted_db_total": findings_persisted_total,
            "findings_capped_not_persisted_total": findings_capped_total_sum,
            "db_persistence_status": db_persistence_status,
            "detector_pipeline_status": detector_pipeline_status,
            "detector_status": detector_pipeline_status,
            "execution_status": run_aggregate,
            "scan_execution_complete": scan_execution_complete,
        },
        "outputs": {
            "reports_output_dir_hint": str(outcome.base_dir),
            "sample_report_relative_paths": paths_sample,
        },
    }

    # Global string caveat applies whenever any profile app has splits.
    max_splits = max(
        ([int(getattr(a, "discovered_artifacts", 0) or 0) for a in outcome.results] + [1]),
        default=1,
    )
    sess_string_note: dict[str, object] = {
        "string_summary_scope": "base_apk_only",
        "discovered_max_artifacts_per_app": max_splits,
    }
    if max_splits > 1:
        sess_string_note["string_summary_warning"] = (
            "split_specific_strings_not_in_post_summary: analyse_string_payload is invoked on "
            "the base APK only per app."
        )
    payload["string_summary_note"] = sess_string_note

    payload["web_session_health_alignment"] = {
        "reference_mysql_views": [
            "v_web_static_session_health",
            "v_web_app_sessions",
        ],
        "session_stamp_for_mysql_join": session_stamp,
        "semantics_note": (
            "MySQL session_usability aggregates DB row presence (findings, permissions, strings"
            "; v_web_static_session_health also audits and run links per app-run). "
            "This document's ``final_run_status`` / ``final_status`` reflect scan/reconciliation "
            "heuristics without querying those auxiliary tables."
        ),
        "cli_can_approximate_mysql_columns": [
            "findings_ready",
            "findings_runtime_total",
            "findings persist/cap rollup fields on static_analysis_runs (once mirrored)",
        ],
        "mysql_only_until_queried": [
            "permissions_ready",
            "strings_ready",
            "audit_ready",
            "link_ready",
            "exact session_usability / is_usable_complete",
        ],
        "per_app_projections_note": (
            "Per-app approximation lives on each ``apps[].mysql_web_session_health_projection`` entry "
            "in ``apps`` array order."
        ),
    }

    return payload
