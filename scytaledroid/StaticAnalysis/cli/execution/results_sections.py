"""Rendering helpers for static analysis CLI results sections."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages
from scytaledroid.Utils.evidence_store import filesystem_safe_slug

from ..core.models import RunOutcome, RunParameters
from .output_mode import compact_success_output_enabled


def _format_counter_value(value: object) -> str:
    return "—" if value is None else str(value)


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value or default)
    except Exception:
        return default


def _print_heading(title: str, underline: str = "-") -> None:
    print(title)
    print(underline * len(title))


def render_static_output_context(context: Mapping[str, object]) -> None:
    """Render static-analysis run context.

    Normal mode uses a compact summary. Verbose mode keeps the older expanded
    Stage Context / Acquisition Counters output.
    """
    acquisition = context.get("acquisition") if isinstance(context.get("acquisition"), Mapping) else {}

    if compact_success_output_enabled():
        _print_heading("Run Context")
        print(f"Session  : {context.get('session_id') or 'n/a'}")
        print(f"Device   : {context.get('device_serial') or 'n/a'}")
        print(f"Scope    : {context.get('scope_analyzed') or 'n/a'}")
        print(f"Mode     : {context.get('mode_label') or 'n/a'}")
        print(
            "Analyzed : "
            f"{_format_counter_value(context.get('analyzed_apps'))} app(s), "
            f"{_format_counter_value(context.get('observed_artifacts'))} artifact(s)"
        )
        print(
            "Harvest  : "
            f"{_format_counter_value(acquisition.get('harvested'))} harvested, "
            f"{_format_counter_value(acquisition.get('persisted'))} persisted"
        )
        blocked_policy = acquisition.get("blocked_policy")
        blocked_scope = acquisition.get("blocked_scope")
        if blocked_policy or blocked_scope:
            print(
                "Blocked  : "
                f"policy={_format_counter_value(blocked_policy)} "
                f"scope={_format_counter_value(blocked_scope)}"
            )
        print()
        return

    _print_heading("Stage Context")
    print("Stage           : Static Analysis")
    print("Purpose         : Analyze harvested APK artifacts only")
    print(f"Session ID      : {context.get('session_id') or 'n/a'}")
    print(f"Device serial   : {context.get('device_serial') or 'n/a'}")
    print(f"Inventory snap  : {_format_counter_value(context.get('snapshot_id'))}")
    print(f"Scope analyzed  : {context.get('scope_analyzed') or 'n/a'}")
    print(f"Mode            : {context.get('mode_label') or 'n/a'}")
    print(f"Analyzed apps   : {_format_counter_value(context.get('analyzed_apps'))}")
    print(f"Artifacts       : {_format_counter_value(context.get('observed_artifacts'))}")
    print()

    _print_heading("Acquisition Counters")
    ordered_keys = (
        ("Inventoried", "inventoried"),
        ("In scope", "in_scope"),
        ("Policy eligible", "policy_eligible"),
        ("Scheduled", "scheduled"),
        ("Harvested", "harvested"),
        ("Harvest persisted", "persisted"),
        ("Blocked policy", "blocked_policy"),
        ("Blocked scope", "blocked_scope"),
    )
    for label, key in ordered_keys:
        print(f"{label:<16}: {_format_counter_value(acquisition.get(key))}")
    print("Note            : Static analysis only uses harvested/persisted artifacts.")
    print()

    _print_heading("Device reality")
    print(f"Total inventoried packages : {_format_counter_value(acquisition.get('inventoried'))}")
    print()

    _print_heading("Acquired for analysis")
    print(f"Harvested packages        : {_format_counter_value(acquisition.get('harvested'))}")
    print(f"Harvest persisted packages: {_format_counter_value(acquisition.get('persisted'))}")
    print(f"Analyzed applications     : {_format_counter_value(context.get('analyzed_apps'))}")
    print(f"Analyzed artifacts        : {_format_counter_value(context.get('observed_artifacts'))}")
    print()

    _print_heading("Not analyzed")
    print(f"Blocked by policy         : {_format_counter_value(acquisition.get('blocked_policy'))}")
    print(f"Blocked by scope          : {_format_counter_value(acquisition.get('blocked_scope'))}")
    print()


def render_static_output_context_compact(
    context: Mapping[str, object],
    *,
    planned_artifacts: int,
    observed_artifacts: int,
) -> None:
    acquisition = context.get("acquisition") if isinstance(context.get("acquisition"), Mapping) else {}
    analyzed_apps = _format_counter_value(context.get("analyzed_apps"))
    inventory = _format_counter_value(context.get("snapshot_id"))
    inventoried = _format_counter_value(acquisition.get("inventoried"))
    blocked_policy = _format_counter_value(acquisition.get("blocked_policy"))
    blocked_scope = _format_counter_value(acquisition.get("blocked_scope"))

    _print_heading("Batch Context")
    print(f"Session       : {context.get('session_id') or 'n/a'}")
    print(f"Device        : {context.get('device_serial') or 'n/a'}")
    print(f"Inventory     : snapshot {inventory} | inventoried={inventoried}")
    print(f"Scope         : {context.get('scope_analyzed') or 'n/a'}")
    print(f"Mode          : {context.get('mode_label') or 'n/a'}")
    print(
        "Analyzed      : "
        f"{analyzed_apps} apps | {observed_artifacts}/{max(int(planned_artifacts or 0), 0)} artifacts"
    )
    print(f"Blocked       : policy={blocked_policy} scope={blocked_scope}")
    print()


def render_session_meta_details(session_meta: object) -> None:
    attempts = getattr(session_meta, "attempts", None)
    canonical_id = getattr(session_meta, "canonical_id", None)
    latest_id = getattr(session_meta, "latest_id", None)
    first_id = getattr(session_meta, "first_static_run_id", None)
    stamp = getattr(session_meta, "session_stamp", None) or getattr(session_meta, "session_label", None)

    if not (attempts is not None or canonical_id is not None or latest_id is not None):
        return

    if compact_success_output_enabled():
        cohort = attempts is not None and attempts > 1
        if cohort:
            print("Session identity (cohort / profile scope):")
            print(f"  Session stamp        : {stamp or 'n/a'}")
            print(
                "  Static run rows      : "
                f"{attempts} (one MariaDB static_analysis_runs row per app in this session)"
            )
            if first_id is not None:
                print(f"  First static_run_id  : {first_id}")
            if latest_id is not None:
                print(f"  Latest static_run_id : {latest_id}")
            if canonical_id is not None:
                print(
                    "  Canonical baseline id: "
                    f"{canonical_id} (paper-grade baseline marker when present)"
                )
            print(
                "  Note                 : latest/canonical ids label rows in static_analysis_runs, "
                "not a single “group run” surrogate key."
            )
            print()
            return

        parts: list[str] = []
        if stamp:
            parts.append(f"session_stamp={stamp}")
        if latest_id is not None:
            parts.append(f"latest_static_run_id={latest_id}")
        if canonical_id is not None:
            parts.append(f"canonical_static_run_id={canonical_id}")
        if attempts is not None:
            parts.append(f"static_run_rows={attempts}")
        if parts:
            print("Run identity: " + " | ".join(parts))
            print()
        return

    _print_heading("Run Identity")
    if attempts is not None:
        print(f"Apps attempted         : {attempts}")
        print(f"Canonical runs finalized: {attempts}")
    if latest_id is not None:
        print(f"Latest static run id   : {latest_id}")
    if canonical_id is not None:
        print(f"Session baseline id    : {canonical_id}")
    print()


def render_artifact_completeness(
    *,
    planned_artifacts: int,
    observed_artifacts: int,
) -> None:
    planned = max(_safe_int(planned_artifacts), 0)
    observed = max(_safe_int(observed_artifacts), 0)
    completeness_pct = int(round((observed / planned) * 100.0)) if planned else 0
    drift_label = "none" if planned == observed else f"planned={planned} observed={observed}"

    if compact_success_output_enabled():
        suffix = "" if planned == observed else f" ({drift_label})"
        print(f"Artifacts: {observed}/{planned} complete ({completeness_pct}%){suffix}")
        print()
        return

    _print_heading("Artifact Completeness")
    print(f"Planned artifacts  : {planned}")
    print(f"Observed artifacts : {observed}")
    print(f"Completeness       : {observed}/{planned} ({completeness_pct}%)")
    print(f"Drift              : {drift_label}")
    print()


def render_static_interpretation_footer() -> None:
    if compact_success_output_enabled():
        return

    _print_heading("Interpretation")
    print("This static analysis applies to harvested APK artifacts only.")
    print("Blocked or unreadable packages were not statically analyzed here.")
    print("Composite grades summarize static structural exposure, not runtime behavior.")
    print()


def _resolve_persistence_audit_path(session_stamp: str | None) -> Path | None:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        return None

    base = Path("output") / "audit" / "persistence"
    candidates = (
        base / f"{stamp}_persistence_audit.json",
        base / f"{stamp}_missing_run_ids.json",
    )
    return next((path for path in candidates if path.exists()), None)


def _resolve_permission_snapshot_path(session_stamp: str | None) -> Path | None:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        return None

    snapshot_id = f"perm-audit:app:{stamp}"
    candidate = Path("data") / "audit" / filesystem_safe_slug(snapshot_id) / "snapshot.json"
    return candidate if candidate.exists() else None


def _mapping_section(payload: Mapping[str, object], key: str) -> Mapping[str, object]:
    section = payload.get(key)
    return section if isinstance(section, Mapping) else {}


def _permission_snapshot_prevalence_sequences(payload: Mapping[str, object]) -> tuple[Sequence[object], Sequence[object]]:
    """Resolve permission/signal prevalence lists from snapshot JSON.

    Current snapshots nest under ``permission_prevalence``; older artifacts may
    use top-level ``permissions`` / ``signals``.
    """

    def _as_sequence(obj: object) -> Sequence[object]:
        if isinstance(obj, Sequence) and not isinstance(obj, (str, bytes, bytearray)):
            return obj
        return ()

    nested = payload.get("permission_prevalence")
    if isinstance(nested, Mapping):
        return _as_sequence(nested.get("permissions")), _as_sequence(nested.get("signals"))
    return _as_sequence(payload.get("permissions")), _as_sequence(payload.get("signals"))


def render_persistence_audit_summary_section(session_stamp: str | None) -> None:
    path = _resolve_persistence_audit_path(session_stamp)
    if path is None:
        print(status_messages.status("Persistence audit artifact not found.", level="warn"))
        return

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(status_messages.status(f"Failed to read persistence audit: {exc}", level="warn"))
        return

    summary = _mapping_section(payload, "summary")
    outcome_summary = _mapping_section(summary, "outcome")
    canonical = _mapping_section(summary, "canonical")
    reconciliation = _mapping_section(summary, "reconciliation")
    reports = _mapping_section(summary, "reports")
    print()
    _print_heading("Persistence audit summary")
    print(f"Artifact : {path}")
    print(f"Schema   : {payload.get('schema_version') or 'unknown'}")
    print(f"Apps     : {payload.get('total_apps') or 0}")

    if outcome_summary:
        compat_stage = outcome_summary.get("compat_export_stage")
        print(
            "Outcome  : "
            f"canonical_failed={bool(outcome_summary.get('canonical_failed', False))} "
            f"persistence_failed={bool(outcome_summary.get('persistence_failed', False))} "
            f"compat_export_failed={bool(outcome_summary.get('compat_export_failed', False))}"
        )
        if compat_stage:
            print(f"Compat stage (export): {compat_stage}")

    if canonical:
        statuses = canonical.get("run_statuses") or {}
        print()
        _print_heading("Canonical persistence", underline="-")
        print(f"  Run statuses      : {statuses}")
        print(f"  Findings (rows)   : {canonical.get('findings', 0)}")
        print(f"  Permission matrix : {canonical.get('permission_matrix', 0)}")
        print(f"  Permission risk   : {canonical.get('permission_risk', 0)}")
        print(f"  Static handoff    : {canonical.get('handoff_paths', 0)} path(s) recorded")

    print()
    _print_heading("Legacy mirror (removed)", underline="-")
    print("  Static analysis no longer writes runs/metrics/buckets/legacy findings.")
    print("  Historical audit JSON may still list mirror counts from older pipeline versions.")

    if reports:
        archive_n = _safe_int(reports.get("archive_json_paths"))
        print()
        _print_heading("Reports (paths recorded on artifacts)", underline="-")
        print(f"  JSON paths total  : {reports.get('json_report_paths', 0)}")
        print(f"  Under latest/     : {reports.get('latest_json_paths', 0)}")
        print(f"  Under archive/    : {archive_n}")
        if archive_n == 0:
            print(
                "  Note              : outcomes usually record the latest/ JSON path; archive/ may still exist "
                "on disk when SCYTALEDROID_STATIC_REPORT_JSON_MODE is archive or both. "
                "Each JSON filename is keyed by SHA-256, so split APK reports do not overwrite one another."
            )

    if reconciliation:
        gap_items = [
            ("missing_legacy_runs_count", "compat runs"),
            ("missing_legacy_risk_count", "compat risk"),
            ("missing_secondary_compat_mirror_count", "secondary compat mirrors"),
            ("missing_findings_summary_count", "findings summary"),
            ("missing_string_summary_count", "string summary"),
            ("bridge_only_runs_count", "compat-only runs"),
            ("bridge_only_risk_count", "compat-only risk"),
        ]
        active_gaps = [
            f"{label}={reconciliation.get(key, 0)}"
            for key, label in gap_items
            if _safe_int(reconciliation.get(key, 0)) > 0
        ]
        print()
        print("Gaps     : " + (", ".join(active_gaps) if active_gaps else "none"))
    else:
        print()
        print("Gaps     : none")

    print()
    print("Note     : Compatibility counts are secondary checks; canonical rows remain authoritative.")


def render_permission_snapshot_summary_section(session_stamp: str | None) -> None:
    path = _resolve_permission_snapshot_path(session_stamp)
    if path is None:
        print(status_messages.status("Permission snapshot artifact not found.", level="warn"))
        return

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(status_messages.status(f"Failed to read permission snapshot: {exc}", level="warn"))
        return

    inventory = _mapping_section(payload, "inventory")
    permissions, signals = _permission_snapshot_prevalence_sequences(payload)

    print()
    _print_heading("Permission audit snapshot (prevalence catalog)")
    print(f"Artifact : {path}")
    print(
        "Apps     : "
        f"total={inventory.get('apps_total', 0)} in_scope={inventory.get('apps_in_scope', 0)}"
    )

    cohort_counts = inventory.get("cohort_counts")
    if isinstance(cohort_counts, Mapping):
        preview = ", ".join(f"{k}={v}" for k, v in list(cohort_counts.items())[:5])
        if preview:
            print(f"Cohorts  : {preview}")

    print(f"Distinct permission names (session rollup) : {len(permissions)}")
    print(f"Distinct signal names (session rollup)     : {len(signals)}")
    print(
        "Note: These counts summarize unique permission/signal names in the permission-audit JSON "
        "(prevalence rollup), not MariaDB permission_matrix row counts. For DB rows, see the persistence audit."
    )


def render_export_all_tables_section(session_stamp: str | None) -> None:
    print()
    _print_heading("Export paths")
    stamp = str(session_stamp or "").strip()

    normalized_csv = Path("output") / "tables" / f"{stamp}_normalized_findings.csv" if stamp else None
    persistence_audit = _resolve_persistence_audit_path(stamp)
    permission_snapshot = _resolve_permission_snapshot_path(stamp)
    report_latest = Path("output") / "reports" / "static" / "latest"

    if normalized_csv is not None:
        print(f"Normalized findings CSV : {normalized_csv}")
    if persistence_audit is not None:
        print(f"Persistence audit       : {persistence_audit}")
    if permission_snapshot is not None:
        print(f"Permission snapshot     : {permission_snapshot}")
    print(f"Static HTML reports     : {report_latest}")


def _print_post_run_diagnostics_header(outcome: RunOutcome, params: RunParameters, *, persist_enabled: bool) -> None:
    stamp = str(params.session_stamp or "").strip()
    packages = [str(getattr(a, "package_name", "") or "").strip() for a in outcome.results]
    packages = [p for p in packages if p]
    if len(packages) == 1:
        pkg_line = packages[0]
    elif packages:
        pkg_line = f"{len(packages)} packages"
    else:
        pkg_line = "n/a"

    run_ids = [
        int(a.static_run_id)
        for a in outcome.results
        if getattr(a, "static_run_id", None) is not None
    ]
    if len(run_ids) == 1:
        rid = str(run_ids[0])
    elif run_ids:
        rid = ", ".join(str(r) for r in run_ids[:4]) + ("…" if len(run_ids) > 4 else "")
    else:
        rid = "n/a"

    db_line = "enabled" if persist_enabled else "skipped"
    gov = "paper-grade requested" if getattr(params, "paper_grade_requested", False) else "experimental path"
    overall = getattr(outcome, "run_aggregate_status", None) or "unknown"

    print(f"Post-run diagnostics — {stamp or 'session'} | static_run_id={rid}")
    print(f"Session        : {stamp or 'n/a'}")
    print(f"Package        : {pkg_line}")
    print(f"Static run ID  : {rid}")
    print(f"DB persistence : {db_line}")
    print(f"Governance     : {gov}")
    print(f"Overall health : {overall}")


def render_db_verification_sql_section(
    *,
    static_run_id: int | None,
    session_stamp: str | None,
    package_name: str | None,
    cohort_multi_app: bool = False,
    example_static_run_id: int | None = None,
) -> None:
    print()
    _print_heading("DB verification SQL")
    stamp = str(session_stamp or "").strip()
    pkg = str(package_name or "").strip()
    print("Paste into your MariaDB analyst shell (adjust catalog/database if needed).")
    print()
    if cohort_multi_app and stamp:
        ex = int(example_static_run_id or static_run_id or 0)
        print(f"-- Group / profile session session_stamp={stamp!r}")
        print("-- Verify cohort-wide counts (join through static_analysis_runs).")
        print()
        print(f"SELECT COUNT(*) AS static_run_rows FROM static_analysis_runs WHERE session_stamp={stamp!r};")
        print(
            "SELECT COUNT(*) AS findings_rows FROM static_analysis_findings f "
            "JOIN static_analysis_runs r ON r.id = f.run_id "
            f"WHERE r.session_stamp={stamp!r};"
        )
        print(
            "SELECT COUNT(*) AS perm_matrix_rows FROM static_permission_matrix m "
            "JOIN static_analysis_runs r ON r.id = m.run_id "
            f"WHERE r.session_stamp={stamp!r};"
        )
        print(f"SELECT * FROM static_session_rollups WHERE session_stamp={stamp!r} LIMIT 5;")
        print(
            "SELECT static_run_id, package_name, session_stamp, status FROM v_web_app_sessions "
            f"WHERE session_stamp={stamp!r} LIMIT 25;"
        )
        print()
        if ex > 0:
            print(f"-- Example single-app drill-down (static_run_id={ex})")
            print(f"SELECT * FROM static_analysis_runs WHERE id = {ex};")
            print(f"SELECT COUNT(*) AS c FROM static_analysis_findings WHERE run_id = {ex};")
            print(f"SELECT COUNT(*) AS c FROM static_permission_matrix WHERE run_id = {ex};")
            print(f"SELECT COUNT(*) AS c FROM static_string_summary WHERE static_run_id = {ex};")
            print(f"SELECT * FROM v_static_handoff_v1 WHERE static_run_id = {ex};")
        print()
        print(
            "Note: normalized findings use run_id → static_analysis_runs.id. "
            "v_web_app_sessions filters may hide superseded rows."
        )
        return

    if static_run_id is None:
        print(status_messages.status("No static_run_id on this outcome — check session linkage / run_health.json.", level="warn"))
        return

    sid = int(static_run_id)
    print(f"-- Context: session_stamp={stamp!r} package={pkg!r} static_run_id={sid}")
    print()
    print(f"SELECT * FROM static_analysis_runs WHERE id = {sid};")
    print(f"SELECT COUNT(*) AS c FROM static_analysis_findings WHERE run_id = {sid};")
    print(f"SELECT COUNT(*) AS c FROM static_permission_matrix WHERE run_id = {sid};")
    print(f"SELECT COUNT(*) AS c FROM static_string_summary WHERE static_run_id = {sid};")
    print(f"SELECT COUNT(*) AS c FROM static_session_run_links WHERE static_run_id = {sid};")
    print(f"SELECT * FROM v_static_handoff_v1 WHERE static_run_id = {sid};")
    print(
        "SELECT static_run_id, package_name, session_stamp, status FROM v_web_app_sessions "
        f"WHERE static_run_id = {sid};"
    )
    print(f"SELECT COUNT(*) AS c FROM v_web_app_findings WHERE static_run_id = {sid};")
    print(f"SELECT COUNT(*) AS c FROM v_web_app_permissions WHERE static_run_id = {sid};")
    print(f"SELECT * FROM v_web_app_findings WHERE static_run_id = {sid} LIMIT 20;")
    print()
    print(
        "Note: v_web_app_* views may filter or dedupe (for example latest-by-package). "
        "Compare counts to canonical static_analysis_* tables if numbers diverge."
    )


def render_static_handoff_diagnostic_section(*, static_run_id: int | None, package_name: str | None) -> None:
    print()
    _print_heading("Static-to-dynamic handoff")
    pkg = str(package_name or "").strip() or "n/a"
    print(f"package_name    : {pkg}")
    if static_run_id is None:
        print(status_messages.status("No static_run_id — cannot query v_static_handoff_v1.", level="warn"))
        return

    sid = int(static_run_id)
    print(f"static_run_id   : {sid}")
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        rows = core_q.run_sql(
            "SELECT * FROM v_static_handoff_v1 WHERE static_run_id = %s LIMIT 3",
            (sid,),
            fetch="all_dict",
        )
    except Exception as exc:
        print(status_messages.status(f"Database query failed (is MariaDB configured?): {exc}", level="warn"))
        return

    if not rows:
        print(
            "No rows in v_static_handoff_v1 for this static_run_id. "
            "The view requires COMPLETED runs with handoff hashes populated — "
            "check static_analysis_runs.status and static_handoff_json_path."
        )
        return

    row = rows[0]
    print(f"static_handoff_hash   : {row.get('static_handoff_hash')}")
    print(f"handoff JSON path     : {row.get('static_handoff_json_path')}")
    print(f"artifact_set_hash     : {row.get('artifact_set_hash')}")
    print(f"base_apk_sha256       : {row.get('base_apk_sha256')}")
    print(f"identity_mode         : {row.get('identity_mode')}")
    print("Dynamic readiness      : see handoff JSON + dynamic plan artifacts for linkage.")


def render_post_run_diagnostics_menu(
    *,
    outcome: RunOutcome,
    params: RunParameters,
    permission_profiles: Sequence[dict[str, object]],
    component_profiles: Sequence[dict[str, object]],
    masvs_matrix: Mapping[str, Mapping[str, object]],
    static_risk_rows: Sequence[dict[str, object]],
    secret_profiles: Sequence[dict[str, object]],
    finding_profiles: Sequence[dict[str, object]],
    trend_deltas: Sequence[dict[str, object]],
    persist_enabled: bool,
    compact_mode: bool,
    render_db_severity_table_fn,
    render_post_run_views_fn,
    render_db_masvs_summary_fn,
    render_cross_app_insights_fn,
) -> None:
    first_pkg = ""
    if outcome.results:
        first_pkg = str(getattr(outcome.results[0], "package_name", "") or "").strip()
    primary_run_id = None
    for app in outcome.results:
        rid = getattr(app, "static_run_id", None)
        if rid is not None:
            primary_run_id = int(rid)
            break

    while True:
        print()
        _print_post_run_diagnostics_header(outcome, params, persist_enabled=persist_enabled)
        print()
        _print_heading("Menu")
        print("1) Findings summary (normalized)")
        print("2) Permission matrix")
        print("3) MASVS matrix")
        print("4) Static risk scores")
        print("5) Aggregate insights")
        print("6) Persistence audit")
        print("7) Permission audit snapshot (prevalence)")
        print("8) Static-to-dynamic handoff")
        print("9) DB verification SQL")
        print("10) Export paths")
        print("0) Back")

        choice = prompt_utils.prompt_text("Choice", default="0", required=False).strip()
        if choice in {"", "0"}:
            break

        if choice == "1":
            printed = False
            if params.session_stamp and persist_enabled:
                printed = render_db_severity_table_fn(params.session_stamp)
            if not printed:
                from ..views.run_detail_view import render_app_table

                render_app_table(outcome.results, diagnostic=params.dry_run, compact=compact_mode)

        elif choice == "2":
            render_post_run_views_fn(
                permission_profiles,
                {},
                [],
                scope_label=params.scope_label,
                snapshot_at=outcome.finished_at,
            )

        elif choice == "3":
            render_post_run_views_fn(
                [],
                masvs_matrix,
                [],
                scope_label=params.scope_label,
                snapshot_at=outcome.finished_at,
            )
            if persist_enabled:
                render_db_masvs_summary_fn()

        elif choice == "4":
            render_post_run_views_fn(
                [],
                {},
                static_risk_rows,
                scope_label=params.scope_label,
                snapshot_at=outcome.finished_at,
            )

        elif choice == "5":
            render_cross_app_insights_fn(
                permission_profiles,
                component_profiles,
                masvs_matrix,
                secret_profiles,
                finding_profiles,
                trend_deltas,
                scope_label=params.scope_label,
            )

        elif choice == "6":
            render_persistence_audit_summary_section(params.session_stamp)

        elif choice == "7":
            render_permission_snapshot_summary_section(params.session_stamp)

        elif choice == "8":
            render_static_handoff_diagnostic_section(
                static_run_id=primary_run_id,
                package_name=first_pkg or None,
            )

        elif choice == "9":
            cohort_multi = len(outcome.results) > 1
            example_sid = primary_run_id
            if cohort_multi and outcome.results:
                last = outcome.results[-1]
                rid = getattr(last, "static_run_id", None)
                if rid is not None:
                    example_sid = int(rid)
            render_db_verification_sql_section(
                static_run_id=primary_run_id,
                session_stamp=params.session_stamp,
                package_name=first_pkg or None,
                cohort_multi_app=cohort_multi,
                example_static_run_id=example_sid,
            )

        elif choice == "10":
            render_export_all_tables_section(params.session_stamp)

        else:
            print(status_messages.status("Invalid selection.", level="warn"))