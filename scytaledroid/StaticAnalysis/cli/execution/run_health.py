"""Run- and app-level health summaries for static analysis (telemetry rollup, audit JSON).

V1 aggregates per-artifact pipeline metadata already produced by detector runs — no detector
behavior changes — and writes one ``run_health.json`` per CLI session directory after persistence.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from ..core.models import AppRunResult, RunOutcome, RunParameters, ScopeSelection

_FINAL_STATUSES = frozenset({"complete", "partial", "failed", "skipped"})


def sanitize_session_stamp_for_filename(session_stamp: str | None) -> str:
    """Return a filesystem-friendly token for tagging ``run_health`` JSON files."""
    token = str(session_stamp or "unknown-session").strip()
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in token).strip("_")
    return cleaned[:120] if cleaned else "unknown-session"


def merge_skipped_detectors(skip_rows: Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    """Deduplicate skipped-detector rows while preserving detector/section/reason."""
    merged: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in skip_rows:
        if not isinstance(row, Mapping):
            continue
        det = str(row.get("detector") or "").strip()
        sec = str(row.get("section") or "").strip()
        reason = str(row.get("reason") or "").strip()
        key = (det, sec, reason)
        if key in seen:
            continue
        seen.add(key)
        merged.append(
            {
                "detector": det or "?",
                "section": sec,
                "reason": reason or "unspecified",
            }
        )
    return merged


def rollup_parse_fallback_signals(app_result: AppRunResult) -> dict[str, int]:
    resource_fallback_art = 0
    bounds_warn_art = 0
    label_or_resource_parse_signals = 0
    for artifact in getattr(app_result, "artifacts", []) or []:
        report = getattr(artifact, "report", None)
        meta = getattr(report, "metadata", None)
        if not isinstance(meta, Mapping):
            continue
        lf = str(meta.get("label_fallback") or "").strip().lower()
        lbl_signal = lf in {"aapt2", "aapt2-localized"} or bool(meta.get("parse_error_resources"))

        fb = meta.get("resource_fallback")
        if isinstance(fb, Mapping) and bool(fb.get("fallback_used")):
            resource_fallback_art += 1
        rbw = meta.get("resource_bounds_warnings")
        if isinstance(rbw, list) and rbw:
            bounds_warn_art += 1

        if lbl_signal:
            label_or_resource_parse_signals += 1

    parse_fallback_events = resource_fallback_art + bounds_warn_art + label_or_resource_parse_signals
    return {
        "resource_fallback_used_artifacts": resource_fallback_art,
        "resource_bounds_warning_artifacts": bounds_warn_art,
        "label_parse_signal_artifacts": label_or_resource_parse_signals,
        "parse_fallback_events_est": parse_fallback_events,
    }


def string_summary_signals(
    base_string_data: Mapping[str, object] | None,
    *,
    discovered_artifacts: int,
) -> dict[str, object]:
    """Describe post-run analyse_string_payload rollup (base APK only when splits exist)."""
    scope = "base_apk_only"
    warning: str | None = None
    if discovered_artifacts > 1:
        warning = (
            "split_specific_strings_not_in_post_summary: post-run analyse_string_payload uses "
            "the base APK path only"
        )

    warnings_list: Sequence[object] = ()
    ok = True
    if isinstance(base_string_data, Mapping):
        raw_w = base_string_data.get("warnings")
        if isinstance(raw_w, list):
            warnings_list = tuple(raw_w)
            if raw_w:
                ok = False
    string_summary_status = "ok" if ok and not warnings_list else "warnings"

    out: dict[str, object] = {
        "string_summary_scope": scope,
        "string_summary_status": string_summary_status,
        "discovered_artifacts_for_note": discovered_artifacts,
    }
    if warning:
        out["string_summary_warning"] = warning
    if warnings_list:
        out["string_summary_messages"] = [str(item) for item in warnings_list if item][:20]
    return out


def compute_app_final_status(
    app_result: AppRunResult,
    *,
    persistence_enabled: bool,
    persist_attempted_this_run: bool,
) -> str:
    """Return ``complete`` / ``partial`` / ``failed`` / ``skipped`` for one app.

    V1 heuristic (scan-phase; persistence reconciliation may downgrade in
    ``reconcile_app_final_status_after_persistence``):

    - **skipped**: harvest / policy excluded before substantive scan (exploratory-only gate).
    - **failed**: nothing useful was produced despite expecting artifacts.
    - **complete**: expected artifacts yielded reports; no detector errors/policy fails;
      no WARN outcomes; persistence did not fault (when persistence is enabled).
    - **partial**: at least one report exists but some gaps, warnings, or fallbacks occurred.
    """
    exploratory = bool(getattr(app_result, "exploratory_only", False))
    disc = int(getattr(app_result, "discovered_artifacts", 0) or 0)
    success_n = len(getattr(app_result, "artifacts", []) or ())
    failed_n = int(getattr(app_result, "failed_artifacts", 0) or 0)

    if exploratory and disc == 0 and success_n == 0:
        return "skipped"

    if disc == 0:
        return "failed"

    if success_n == 0:
        return "failed"

    from .scan_report import _summarize_app_pipeline

    summary = _summarize_app_pipeline(app_result)

    errs = int(summary.get("error_count", 0) or 0)
    fails = int(summary.get("fail_count", 0) or 0)
    warns = int(summary.get("warn_count", 0) or 0)

    persisted_db_issue = False
    if persistence_enabled and persist_attempted_this_run:
        persisted_db_issue = bool(
            getattr(app_result, "persistence_failure_stage", None)
            or getattr(app_result, "persistence_exception_class", None)
        )

    str_sig = string_summary_signals(
        getattr(app_result, "base_string_data", None),
        discovered_artifacts=disc,
    )
    str_status = str(str_sig.get("string_summary_status") or "ok")

    parse_events = int(summary.get("parse_fallback_events_est", 0) or 0)

    strict_scan_ok = (
        failed_n == 0
        and success_n == disc
        and errs == 0
        and fails == 0
        and warns == 0
        and parse_events == 0
        and str_status == "ok"
        and not persisted_db_issue
    )

    if strict_scan_ok:
        return "complete"

    # Any successful report counts as partial rather than outright failed unless everything blew up.
    if success_n >= 1:
        return "partial"

    return "failed"


def reconcile_app_final_status_after_persistence(app_result: AppRunResult, *, persistence_enabled: bool) -> None:
    """Adjust ``final_status`` after DB persistence failures (caller sets phase)."""
    current = getattr(app_result, "final_status", None)
    if current not in _FINAL_STATUSES:
        return
    if current in {"failed", "skipped"}:
        return
    if not persistence_enabled:
        return
    if getattr(app_result, "persistence_failure_stage", None) or getattr(app_result, "persistence_exception_class", None):
        if current == "complete":
            app_result.final_status = "partial"


def compute_run_aggregate_status(outcome: RunOutcome) -> str:
    statuses = [
        getattr(r, "final_status", None) for r in outcome.results if getattr(r, "final_status", None)
    ]
    if not statuses:
        if outcome.aborted:
            return "failed"
        return "failed"

    if outcome.aborted:
        # Surface operator-visible aborted runs as failed at session scope.
        if any(s == "complete" for s in statuses):
            return "partial"
        return "failed"

    ctr = Counter(str(s) for s in statuses)
    if ctr["failed"] == len(statuses):
        return "failed"
    if ctr["skipped"] == len(statuses):
        return "skipped"
    if ctr["complete"] == len(statuses):
        return "complete"
    return "partial"


def _approximate_findings_ready(
    *,
    persistence_enabled: bool,
    persist_attempted: bool,
    persisted_ok_app: bool,
    persisted_findings: int | None,
) -> int | None:
    """Best-effort stand-in for MySQL ``findings_ready`` (1 if row count > 0, else 0).

    Returns ``None`` when this run did not produce a reliable DB-side signal from the CLI.
    """
    if not persistence_enabled or not persist_attempted:
        return None
    if not persisted_ok_app:
        return None
    if not isinstance(persisted_findings, int):
        return None
    return 1 if persisted_findings > 0 else 0


def _web_session_health_projection_for_app(
    app: AppRunResult,
    *,
    persistence_enabled: bool,
    persist_attempted: bool,
    persisted: bool,
    persisted_ok_app: bool,
    rt_pf: object,
    ps_pf: object,
    cap_pf: object,
) -> dict[str, object]:
    """Map MySQL ``v_web_*`` column names to CLI-computable values where possible."""
    findings_ready = _approximate_findings_ready(
        persistence_enabled=persistence_enabled,
        persist_attempted=persist_attempted,
        persisted_ok_app=persisted_ok_app,
        persisted_findings=ps_pf if isinstance(ps_pf, int) else None,
    )
    mysql_only = {
        "permissions_ready": None,
        "strings_ready": None,
        "audit_ready": None,
        "link_ready": None,
        "session_usability": None,
        "is_usable_complete": None,
    }
    cap_json: object | None
    if isinstance(cap_pf, int) and cap_pf > 0:
        cap_json = getattr(app, "persistence_findings_capped_by_detector", None)
    else:
        cap_json = None
    return {
        "approximate_mysql_columns": {
            "findings_ready": findings_ready,
            "findings_runtime_total": rt_pf if isinstance(rt_pf, int) else None,
            "findings_persisted_rowcount_approx": ps_pf if isinstance(ps_pf, int) else None,
            "findings_capped_total": cap_pf if isinstance(cap_pf, int) else None,
            "findings_capped_by_detector_json": cap_json if isinstance(cap_json, Mapping) else None,
        },
        "mysql_only_requires_db_refresh": mysql_only,
    }


def collect_report_paths_for_app(app_result: AppRunResult, limit: int = 24) -> list[str]:
    paths: list[str] = []
    for art in getattr(app_result, "artifacts", []) or []:
        p = getattr(art, "saved_path", None)
        if p and str(p).strip():
            paths.append(str(p))
        if len(paths) >= max(8, limit):
            break
    return paths[:limit]


def build_run_health_document(
    outcome: RunOutcome,
    params: RunParameters,
    *,
    persistence_enabled: bool,
    persist_attempted: bool,
) -> dict[str, object]:
    from .scan_report import _summarize_app_pipeline

    selection: ScopeSelection = outcome.scope

    detector_errors_total = 0
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
            }
        )

    run_aggregate = getattr(outcome, "run_aggregate_status", None) or compute_run_aggregate_status(outcome)

    preset = getattr(params, "profile", None)

    paths_sample: list[str] = []
    for app in outcome.results:
        paths_sample.extend(collect_report_paths_for_app(app, limit=4))
        if len(paths_sample) >= 12:
            paths_sample = paths_sample[:12]
            break

    session_stamp = getattr(params, "session_stamp", None)

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
        "run_rollups": {
            "app_total": len(outcome.results),
            "artifact_total_discovered_estimate": artifact_rows_total,
            "artifacts_scan_completed_counter": scanned_success,
            "apps_complete_final": completed_ct,
            "apps_partial_final": partial_ct,
            "apps_failed_final": failed_ct,
            "apps_skipped_final": skipped_ct,
            "detector_errors_total_estimate": detector_errors_total,
            "parse_fallback_events_total_estimate": parse_fallback_total,
            "string_summary_warning_apps_estimate": string_warn_apps,
            "persist_attempted_this_run": persist_attempted,
            "findings_runtime_total": findings_runtime_total,
            "findings_persisted_db_total": findings_persisted_total,
            "findings_capped_not_persisted_total": findings_capped_total_sum,
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


def write_run_health_json(path: Path, document: Mapping[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(document, indent=2, sort_keys=False, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")
    return path


def compact_run_health_stdout_line(doc: Mapping[str, object]) -> str:
    roll = doc.get("run_rollups") if isinstance(doc.get("run_rollups"), Mapping) else {}
    path = ""
    outp = doc.get("outputs") if isinstance(doc.get("outputs"), Mapping) else {}
    if isinstance(outp, Mapping):
        path = str(outp.get("run_health_json_relative") or outp.get("run_health_json_abs") or "")

    return (
        f"Run health: status={doc.get('final_run_status')} "
        f"apps complete={roll.get('apps_complete_final')}/{roll.get('app_total')} "
        f"partial={roll.get('apps_partial_final')} failed={roll.get('apps_failed_final')} "
        f"skipped={roll.get('apps_skipped_final')} "
        f"detector_errors~={roll.get('detector_errors_total_estimate')} "
        f"path={path}"
    )


def attach_run_health_outputs_on_document(doc: MutableMapping[str, object], *, path: Path, base_dir: Path) -> None:
    outp = dict(doc.get("outputs") if isinstance(doc.get("outputs"), Mapping) else {})
    outp["run_health_json_abs"] = str(path)
    rel = path.name
    try:
        if base_dir.is_absolute():
            rel = str(path.resolve().relative_to(base_dir.resolve()))
        else:
            rel = str(path.relative_to(base_dir))
    except (OSError, ValueError):
        rel = path.name
    outp["run_health_json_relative"] = rel
    doc["outputs"] = outp
