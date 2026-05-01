"""Data health checks for Database Utilities menu."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Database.db_core import permission_intel as intel_db
from scytaledroid.Database.db_core import run_sql
from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils.permission_intel_freeze import (
    list_operational_managed_tables,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from ..health_checks import fetch_latest_run, fetch_latest_session
from ..health_checks.analysis_integrity import fetch_analysis_integrity_summary
from ..health_checks.inventory_checks import run_inventory_snapshot_checks
from ..health_checks.summary import fetch_health_summary
from ..menu_actions import log_db_op
from ..reset_static import (
    HARVEST_TABLES,
    PROTECTED_TABLES,
    STATIC_ANALYSIS_TABLES,
    reset_static_analysis_data,
)
from .health_checks_permission import render_scoring_checks
from .health_checks_inventory import run_inventory_health_check
from .health_checks_bridge import (
    fetch_netstats_missing_summary,
    fetch_network_quality_rollup,
    fetch_pcap_audit_counts,
)
from .health_checks_analysis_overview import (
    count_evidence_integrity_issues,
    fetch_evidence_integrity_issues,
    load_feature_health_report,
    load_feature_health_status,
)
from .health_checks_table_helpers import (
    count_tables,
    print_table_counts,
    print_table_list,
    table_exists,
)
from .health_checks_pipeline import (
    fetch_pcap_backfill_candidates,
    load_pcap_summary_fields,
)
from .health_checks_recompute import (
    fetch_dataset_tier_run_count,
    recompute_network_signal_quality,
)
from .health_checks_static import (
    fetch_findings_detail,
    fetch_string_summary_detail,
    render_integrity_checks,
)
from .sql_helpers import coerce_datetime, scalar


def _column_exists(table: str, column: str) -> bool:
    try:
        row = run_sql(
            """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = %s
              AND column_name = %s
            """,
            (table, column),
            fetch="one",
        )
    except Exception:
        return False
    return bool(row and row[0])


def run_health_summary() -> None:
    """One-screen DB health summary for quick operator checks."""
    print()
    menu_utils.print_header("DB Health Summary")
    menu_utils.print_hint(
        "Quick operator snapshot of runs, orphans, evidence, and governance."
    )

    summary = fetch_health_summary()
    menu_utils.print_section("Run status")
    menu_utils.print_metrics(
        [
            ("RUNNING (total)", summary.running_total if summary.running_total is not None else "—"),
            ("RUNNING (last 24h)", summary.running_recent if summary.running_recent is not None else "—"),
            ("OK (last 24h)", summary.ok_recent if summary.ok_recent is not None else "—"),
            ("FAILED (last 24h)", summary.failed_recent if summary.failed_recent is not None else "—"),
            ("ABORTED (last 24h)", summary.aborted_recent if summary.aborted_recent is not None else "—"),
        ]
    )
    menu_utils.print_section("Static batch watch")
    stale_started_rows = getattr(summary, "stale_started_rows", None)
    stale_started_sessions = getattr(summary, "stale_started_sessions", None)
    stale_started_rows_without_downstream = getattr(
        summary, "stale_started_rows_without_downstream", None
    )
    stale_started_sessions_without_downstream = getattr(
        summary, "stale_started_sessions_without_downstream", None
    )
    menu_utils.print_metrics(
        [
            ("stale_started_rows", f"{stale_started_rows if stale_started_rows is not None else '—'} (>2h)"),
            ("stale_started_sessions", f"{stale_started_sessions if stale_started_sessions is not None else '—'} (>2h)"),
            ("no_downstream_rows", f"{stale_started_rows_without_downstream if stale_started_rows_without_downstream is not None else '—'} (>2h)"),
            (
                "no_downstream_sessions",
                f"{stale_started_sessions_without_downstream if stale_started_sessions_without_downstream is not None else '—'} (>2h, >=5 rows)",
            ),
        ]
    )
    if (stale_started_sessions_without_downstream or 0) > 0:
        print(
            status_messages.status(
                "Deferred static batch persistence appears stale; reports/STARTED rows exist without downstream canonical writes.",
                level="warn",
            )
        )

    menu_utils.print_section("Orphan checks")
    menu_utils.print_metrics(
        [
            ("orphan_findings", summary.orphan_findings if summary.orphan_findings is not None else "—"),
            ("orphan_string_samples", summary.orphan_samples if summary.orphan_samples is not None else "—"),
            ("orphan_string_selected", summary.orphan_selected_samples if summary.orphan_selected_samples is not None else "—"),
            ("orphan_string_sets", summary.orphan_sample_sets if summary.orphan_sample_sets is not None else "—"),
            ("orphan_audit_apps", summary.orphan_audit_apps if summary.orphan_audit_apps is not None else "—"),
        ]
    )

    menu_utils.print_section("Evidence integrity")
    if _column_exists("permission_audit_snapshots", "evidence_relpath"):
        missing_evidence = scalar(
            """
            SELECT COUNT(*)
            FROM permission_audit_snapshots
            WHERE evidence_relpath IS NULL OR evidence_relpath = ''
            """
        )
        missing_hash = scalar(
            """
            SELECT COUNT(*)
            FROM permission_audit_snapshots
            WHERE evidence_sha256 IS NULL OR evidence_sha256 = ''
            """
        )
        menu_utils.print_metrics(
            [
                ("audit_missing_relpath", missing_evidence if missing_evidence is not None else "—"),
                ("audit_missing_sha256", missing_hash if missing_hash is not None else "—"),
            ]
        )
    else:
        print("audit evidence fields  : not tracked")

    menu_utils.print_section("Governance snapshot")
    try:
        gov_headers = intel_db.governance_snapshot_count()
        gov_rows = intel_db.governance_row_count()
        target = intel_db.describe_target()
        duplicates = list_operational_managed_tables()
    except Exception:
        gov_headers = None
        gov_rows = None
        target = {}
        duplicates = []
    menu_utils.print_metrics(
        [
            ("snapshots", gov_headers if gov_headers is not None else "—"),
            ("rows", gov_rows if gov_rows is not None else "—"),
        ]
    )
    menu_utils.print_section("Permission-intel split")
    dup_present = [row for row in duplicates if row["exists"]]
    menu_utils.print_metrics(
        [
            ("target_db", target.get("database") or "—"),
            ("target_source", target.get("source") or "—"),
            ("dup_tables_main", len(dup_present)),
            ("dup_rows_main", sum(int(row["row_count"] or 0) for row in dup_present) if dup_present else 0),
        ]
    )
    if dup_present:
        print(
            "dup_table_preview      : "
            + ", ".join(f"{row['table']}={row['row_count']}" for row in dup_present[:5])
            + (" ..." if len(dup_present) > 5 else "")
        )

    analysis = fetch_analysis_integrity_summary()
    menu_utils.print_section("Analysis/web contracts")
    print(f"dynamic_runs           : {analysis.dynamic_runs if analysis.dynamic_runs is not None else '—'}")
    print(f"dynamic_feature_rows   : {analysis.dynamic_feature_rows if analysis.dynamic_feature_rows is not None else '—'}")
    print(
        "missing_features       : "
        f"{analysis.dynamic_runs_missing_features if analysis.dynamic_runs_missing_features is not None else '—'}"
    )
    print(
        "countable_missing_feat : "
        f"{analysis.countable_runs_missing_features if analysis.countable_runs_missing_features is not None else '—'}"
    )
    print(
        "feature_recency_pkgs   : "
        f"latest_ok={analysis.packages_latest_run_has_features if analysis.packages_latest_run_has_features is not None else '—'} "
        f"older_only={analysis.packages_latest_run_missing_features_older_features_exist if analysis.packages_latest_run_missing_features_older_features_exist is not None else '—'} "
        f"none={analysis.packages_no_feature_rows_for_package if analysis.packages_no_feature_rows_for_package is not None else '—'}"
    )
    print(
        "evidence_paths         : "
        f"tracked={analysis.dynamic_runs_with_evidence_path if analysis.dynamic_runs_with_evidence_path is not None else '—'} "
        f"missing_local={analysis.dynamic_runs_missing_local_evidence if analysis.dynamic_runs_missing_local_evidence is not None else '—'}"
    )
    print(
        "artifact_host_paths    : "
        f"present={analysis.dynamic_artifact_host_paths_present if analysis.dynamic_artifact_host_paths_present is not None else '—'} "
        f"missing={analysis.dynamic_artifact_host_paths_missing if analysis.dynamic_artifact_host_paths_missing is not None else '—'}"
    )
    print(
        "dangling_static_links  : "
        f"{analysis.dynamic_runs_with_dangling_static_id if analysis.dynamic_runs_with_dangling_static_id is not None else '—'}"
    )
    print(
        "artifact_orphans       : "
        f"dynamic={analysis.dynamic_artifact_orphan_rows if analysis.dynamic_artifact_orphan_rows is not None else '—'} "
        f"static={analysis.static_artifact_orphan_rows if analysis.static_artifact_orphan_rows is not None else '—'}"
    )
    print(
        "app_catalog_gaps       : "
        f"no_analysis={analysis.app_catalog_without_analysis if analysis.app_catalog_without_analysis is not None else '—'} "
        f"no_versions={analysis.apps_without_versions if analysis.apps_without_versions is not None else '—'}"
    )
    print(
        "harvest_version_gaps   : "
        f"{analysis.harvested_version_pairs_missing_from_app_versions if analysis.harvested_version_pairs_missing_from_app_versions is not None else '—'}"
    )
    print(
        "app_version_sdk_gaps   : "
        f"target={analysis.app_versions_missing_target_sdk if analysis.app_versions_missing_target_sdk is not None else '—'} "
        f"min={analysis.app_versions_missing_min_sdk if analysis.app_versions_missing_min_sdk is not None else '—'} "
        f"run_target={analysis.referenced_app_versions_missing_target_sdk if analysis.referenced_app_versions_missing_target_sdk is not None else '—'} "
        f"run_min={analysis.referenced_app_versions_missing_min_sdk if analysis.referenced_app_versions_missing_min_sdk is not None else '—'}"
    )
    if (analysis.referenced_app_versions_missing_min_sdk or 0) > 0:
        print(
            "app_version_sdk_note   : "
            "run-backed min_sdk gaps remain; current historical artifacts do not provide a clean backfill source"
        )
    print(
        "app_version_dupes      : "
        f"groups={analysis.duplicate_app_version_code_groups if analysis.duplicate_app_version_code_groups is not None else '—'} "
        f"rows={analysis.duplicate_app_version_rows if analysis.duplicate_app_version_rows is not None else '—'}"
    )
    print(
        "partial_perm_runs      : "
        f"{analysis.interrupted_permission_partial_runs if analysis.interrupted_permission_partial_runs is not None else '—'}"
    )
    print(
        "risk_surface_drift     : "
        f"rows={analysis.risk_surface_rows_with_both_scores if analysis.risk_surface_rows_with_both_scores is not None else '—'} "
        f"score_mismatch={analysis.risk_surface_score_mismatch_rows if analysis.risk_surface_score_mismatch_rows is not None else '—'} "
        f"count_mismatch={analysis.risk_surface_count_mismatch_rows if analysis.risk_surface_count_mismatch_rows is not None else '—'} "
        f"avg_delta={analysis.risk_surface_avg_score_delta if analysis.risk_surface_avg_score_delta is not None else '—'}"
    )
    print(
        "summary_surface        : "
        f"{analysis.static_dynamic_summary_source} "
        f"(cache_rows={analysis.static_dynamic_summary_cache_rows if analysis.static_dynamic_summary_cache_rows is not None else '—'} "
        f"materialized={analysis.static_dynamic_summary_cache_materialized_at or '—'})"
    )
    print(
        "package_collations     : "
        f"{analysis.package_collation_variants if analysis.package_collation_variants is not None else '—'}"
    )
    if analysis.legacy_non_utf8_package_tables:
        print(
            "legacy_non_utf8_pkg   : "
            + ", ".join(analysis.legacy_non_utf8_package_tables)
        )
    print(
        "schema_contracts       : "
        + ("ok" if not analysis.missing_schema_objects else "missing " + ", ".join(analysis.missing_schema_objects))
    )

    prompt_utils.press_enter_to_continue()


def run_health_checks() -> None:
    print()
    menu_utils.print_header("Data Health Checks")
    menu_utils.print_hint(
        "Validate recent static ingestion, linkage, scoring, and integrity."
    )

    latest_run = fetch_latest_run(run_sql)
    latest_session = fetch_latest_session(run_sql)

    if latest_run is None and latest_session is None:
        print(status_messages.status("No runs or summaries recorded yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    static_run_id = int(latest_run.get("static_run_id") or 0) if latest_run else 0
    package = str(
        (latest_run or {}).get("package_name")
        or (latest_session or {}).get("package_name")
        or "<unknown>"
    )
    ts_value = (latest_run or {}).get("created_at")
    ts_dt = coerce_datetime(ts_value)
    session_from_run = (latest_run or {}).get("session_stamp")
    session_stamp = session_from_run or (latest_session or {}).get("session_stamp")
    run_status = (latest_run or {}).get("status") or "—"

    menu_utils.print_section("Ingestion")
    menu_utils.print_metrics([("Latest session", session_stamp or "unknown")])

    if session_stamp:
        findings_total = scalar(
            "SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp = %s",
            (session_stamp,),
        )
        findings_detail = _fetch_findings_detail(session_stamp)
        _print_status_line(
            "ok" if findings_total else "fail",
            "static_findings_summary (baseline)",
            detail=findings_detail or str(findings_total or 0),
        )

        strings_total = scalar(
            "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp = %s",
            (session_stamp,),
        )
        strings_detail = _fetch_string_summary_detail(session_stamp)
        _print_status_line(
            "ok" if strings_total else "fail",
            "static_string_summary",
            detail=strings_detail or str(strings_total or 0),
        )

        findings_rows_total = scalar(
            """
            SELECT COUNT(*)
            FROM static_findings f
            JOIN static_findings_summary s ON s.id = f.summary_id
            WHERE s.session_stamp = %s
            """,
            (session_stamp,),
        )
        if findings_rows_total is not None:
            _print_status_line(
                "ok" if findings_rows_total else "warn",
                "static_findings (baseline detail)",
                detail=str(findings_rows_total or 0),
            )

        provider_total = scalar(
            "SELECT COUNT(*) FROM static_provider_acl WHERE session_stamp = %s",
            (session_stamp,),
        )
        _print_status_line(
            "ok" if provider_total else "warn",
            "static_provider_acl",
            detail=str(provider_total or 0),
        )

        fileproviders_total = scalar(
            "SELECT COUNT(*) FROM static_fileproviders WHERE session_stamp = %s",
            (session_stamp,),
        )
        _print_status_line(
            "ok" if fileproviders_total else "warn",
            "static_fileproviders",
            detail=str(fileproviders_total or 0),
        )

        samples_total = scalar(
            """
            SELECT COUNT(*)
            FROM static_string_samples x
            JOIN static_findings_summary s ON s.id = x.summary_id
            WHERE s.session_stamp = %s
            """,
            (session_stamp,),
        )
        selected_total = scalar(
            """
            SELECT COUNT(*)
            FROM static_string_selected_samples x
            JOIN static_findings_summary s ON s.id = x.summary_id
            WHERE s.session_stamp = %s
            """,
            (session_stamp,),
        )
        if samples_total is not None:
            _print_status_line(
                "ok" if samples_total else "warn",
                "static_string_samples (raw)",
                detail=str(samples_total or 0),
            )
        if selected_total is not None:
            _print_status_line(
                "ok" if selected_total else "warn",
                "static_string_selected",
                detail=str(selected_total or 0),
            )

    else:
        _print_status_line(
            "warn",
            "session_stamp",
            detail="no session stamp recorded; ensure static runs persist summaries",
        )

    print()
    _run_inventory_health_check()

    print()
    menu_utils.print_section("Run Linkage")
    if latest_run:
        run_label = (
            f"static_run_id={static_run_id or '—'}, "
            f"pkg={package}, status={run_status}, ts={ts_dt or ts_value}"
        )
        _print_status_line("ok", "static_analysis_runs", detail=run_label)
    else:
        _print_status_line(
            "warn",
            "static_analysis_runs",
            detail="no rows in canonical static run ledger; run baseline/full analysis to populate",
        )

    print()
    menu_utils.print_section("Scoring & Coverage")
    _render_scoring_checks()

    print()
    menu_utils.print_section("Integrity")
    _render_integrity_checks(session_stamp)

    prompt_utils.press_enter_to_continue()


def run_evidence_integrity_check() -> None:
    """Check DB-only evidence linkage fields for static permission snapshots.

    Note: dynamic evidence packs are verified via Evidence & Workspace, not via DB.
    """
    print()
    menu_utils.print_header("DB Integrity Check (Snapshot Linkage)")
    print(
        status_messages.status(
            "For dynamic evidence packs integrity: Evidence & Workspace -> Verify dynamic evidence packs.",
            level="info",
        )
    )

    if _column_exists("permission_audit_snapshots", "evidence_relpath"):
        missing_relpath = scalar(
            """
            SELECT COUNT(*)
            FROM permission_audit_snapshots
            WHERE evidence_relpath IS NULL OR evidence_relpath = ''
            """
        )
        missing_hash = scalar(
            """
            SELECT COUNT(*)
            FROM permission_audit_snapshots
            WHERE evidence_sha256 IS NULL OR evidence_sha256 = ''
            """
        )
        print(f"audit_missing_relpath : {missing_relpath if missing_relpath is not None else '—'}")
        print(f"audit_missing_sha256  : {missing_hash if missing_hash is not None else '—'}")
    else:
        print("permission_audit_snapshots evidence fields not tracked.")

    prompt_utils.press_enter_to_continue()


def _render_scoring_checks() -> None:
    render_scoring_checks(
        run_sql=run_sql,
        scalar=scalar,
        print_status_line=_print_status_line,
        status_messages=status_messages,
    )


def _render_integrity_checks(session_stamp: str | None) -> None:
    render_integrity_checks(
        run_sql=run_sql,
        print_status_line=_print_status_line,
        session_stamp=session_stamp,
    )


def _fetch_findings_detail(session_stamp: str) -> str | None:
    return fetch_findings_detail(run_sql=run_sql, session_stamp=session_stamp)


def _fetch_string_summary_detail(session_stamp: str) -> str | None:
    return fetch_string_summary_detail(run_sql=run_sql, session_stamp=session_stamp)


def _print_status_line(level: str, label: str, *, detail: str | None = None) -> None:
    line = label
    if detail:
        line += f" ({detail})"
    mapped = {"ok": "success", "warn": "warn", "fail": "error"}.get(level, "info")
    print(status_messages.status(line, level=mapped))


def prompt_cleanup_orphan_inventory() -> None:
    menu_utils.print_header("Cleanup Orphan Inventory Snapshots")
    orphan_count = scalar(
        """
        SELECT COUNT(*)
        FROM device_inventory_snapshots s
        LEFT JOIN device_inventory i ON i.snapshot_id = s.snapshot_id
        WHERE i.snapshot_id IS NULL
        """
    ) or 0
    if orphan_count == 0:
        print(status_messages.status("No orphan inventory snapshots found.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    print(
        status_messages.status(
            f"Found {orphan_count} orphan snapshot header(s) (no inventory rows).",
            level="warn",
        )
    )
    if not prompt_utils.prompt_yes_no("Proceed?", default=False):
        print(status_messages.status("Cleanup cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    run_sql(
        """
        DELETE s
        FROM device_inventory_snapshots s
        LEFT JOIN device_inventory i ON i.snapshot_id = s.snapshot_id
        WHERE i.snapshot_id IS NULL
        """,
    )
    print(status_messages.status("Orphan inventory snapshots deleted.", level="success"))
    prompt_utils.press_enter_to_continue()


def _run_inventory_health_check() -> None:
    run_inventory_health_check(
        menu_utils=menu_utils,
        run_sql=run_sql,
        scalar=scalar,
        print_status_line=_print_status_line,
        run_inventory_snapshot_checks=run_inventory_snapshot_checks,
    )


def prompt_reset_static_data() -> None:
    print()
    menu_utils.print_header("Reset Static Analysis Data")
    print(
        status_messages.status(
            "Destructive static TRUNCATE is maintenance-only and no longer available from menu workflows.",
            level="warn",
        )
    )
    print(
        status_messages.status(
            "Use explicit maintenance command: ./run.sh db --truncate-static --i-understand DESTROY_DATA",
            level="info",
        )
    )
    prompt_utils.press_enter_to_continue()


def run_tier1_audit_report() -> None:
    print()
    menu_utils.print_header("Baseline Audit Report")

    schema_version = diagnostics.get_schema_version() or "<unknown>"
    print(f"Schema version : {schema_version}")
    print()

    required_tables = (
        "dynamic_sessions",
        "dynamic_telemetry_process",
        "dynamic_telemetry_network",
        "dynamic_session_issues",
    )
    missing_tables = [name for name in required_tables if not table_exists(name)]
    _print_status_line(
        "ok" if not missing_tables else "error",
        "required tables",
        detail="ok" if not missing_tables else ", ".join(missing_tables),
    )

    required_columns = (
        "tier",
        "netstats_available",
        "network_signal_quality",
        "netstats_rows",
        "netstats_missing_rows",
        "sampling_duration_seconds",
        "clock_alignment_delta_s",
        "sample_first_gap_s",
        "sample_max_gap_excluding_first_s",
    )
    missing_columns = []
    for column in required_columns:
        if not _column_exists("dynamic_sessions", column):
            missing_columns.append(column)
    _print_status_line(
        "ok" if not missing_columns else "warn",
        "dynamic_sessions columns",
        detail="ok" if not missing_columns else ", ".join(missing_columns),
    )

    stale_running = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='RUNNING'
          AND ended_at_utc IS NULL
        """
    ) or 0
    _print_status_line(
        "ok" if stale_running == 0 else "warn",
        "stale RUNNING rows",
        detail=str(stale_running),
    )

    if _column_exists("dynamic_sessions", "clock_alignment_delta_s"):
        misaligned = scalar(
            """
            SELECT COUNT(*)
            FROM dynamic_sessions
            WHERE tier='dataset'
              AND clock_alignment_delta_s IS NOT NULL
              AND clock_alignment_delta_s > 5
            """
        ) or 0
        _print_status_line(
            "ok" if misaligned == 0 else "warn",
            "clock alignment > 5s",
            detail=str(misaligned),
        )

    tier1_ready = scalar(
        """
        SELECT COUNT(*)
        FROM dynamic_sessions ds
        WHERE ds.tier='dataset'
          AND ds.status='success'
          AND ds.captured_samples / NULLIF(ds.expected_samples,0) >= 0.90
          AND ds.sample_max_gap_s <= (ds.sampling_rate_s * 2)
          AND NOT EXISTS (
            SELECT 1
            FROM dynamic_session_issues i
            WHERE i.dynamic_run_id = ds.dynamic_run_id
              AND i.issue_code = 'telemetry_partial_samples'
          )
        """
    )
    _print_status_line(
        "ok" if tier1_ready and int(tier1_ready) > 0 else "warn",
        "Baseline QA-pass runs",
        detail=str(tier1_ready or 0),
    )

    feature_health_status = load_feature_health_status()
    if feature_health_status:
        _print_status_line(
            "ok" if feature_health_status == "PASS" else "warn" if feature_health_status == "WARN" else "error",
            "Feature Health",
            detail=feature_health_status,
        )
        if feature_health_status == "WARN":
            feature_health = load_feature_health_report()
            if feature_health and feature_health.get("network_channel_excluded"):
                reason = feature_health.get("network_channel_reason") or "network_channel_excluded"
                print(
                    status_messages.status(
                        f"Feature Health WARN due to network channel exclusion ({reason}).",
                        level="info",
                    )
                )
    else:
        _print_status_line("warn", "Feature Health", detail="missing (run export)")

    evidence_missing = count_evidence_integrity_issues(column_exists=_column_exists, scalar=scalar)
    _print_status_line(
        "ok" if evidence_missing == 0 else "warn",
        "evidence integrity (missing fields)",
        detail=str(evidence_missing),
    )
    if evidence_missing:
        if prompt_utils.prompt_yes_no("Show missing evidence details?", default=False):
            rows = fetch_evidence_integrity_issues(limit=25)
            if rows:
                table_rows = [
                    [
                        str(row.get("snapshot_id") or ""),
                        str(row.get("snapshot_key") or ""),
                        str(row.get("run_id") or ""),
                        str(row.get("static_run_id") or ""),
                        "yes" if row.get("missing_relpath") else "no",
                        "yes" if row.get("missing_sha256") else "no",
                    ]
                    for row in rows
                ]
                print()
                table_utils.render_table(
                    [
                        "snapshot_id",
                        "snapshot_key",
                        "run_id",
                        "static_run_id",
                        "missing_relpath",
                        "missing_sha256",
                    ],
                    table_rows,
                    compact=True,
                )
                print()

    pcap_counts = fetch_pcap_audit_counts()
    if pcap_counts:
        linked = pcap_counts.get("linked", 0)
        exists = pcap_counts.get("exists", 0)
        valid = pcap_counts.get("valid", 0)
        detail = f"linked={linked} exists={exists} valid={valid}"
        level = "ok" if linked and valid else "warn"
        _print_status_line(level, "PCAP linkage/validity", detail=detail)

    netstats_summary = fetch_netstats_missing_summary()
    if netstats_summary:
        print(status_messages.status("Baseline netstats missing summary:", level="info"))
        table_rows = [
            [
                row.get("package_name", ""),
                str(row.get("run_count") or 0),
                str(row.get("total_missing") or 0),
                str(row.get("max_missing") or 0),
                row.get("missing_pct", "n/a"),
            ]
            for row in netstats_summary
        ]
        table_utils.render_table(
            ["package_name", "runs", "missing_rows_total", "missing_rows_max", "missing_pct"],
            table_rows,
            compact=True,
        )
        if any(row.get("missing_pct_value", 0) > 0.10 for row in netstats_summary):
            print(
                status_messages.status(
                    "Warning: netstats missing rate exceeds 10% for at least one dataset app.",
                    level="warn",
                )
            )
        print()

    rollup = fetch_network_quality_rollup()
    if rollup:
        rollup_text = ", ".join(f"{row['quality']}={row['runs']}" for row in rollup)
        print(status_messages.status(f"Network quality rollup: {rollup_text}", level="info"))
        print()

    prompt_utils.press_enter_to_continue()


def prompt_finalize_stale_runs() -> None:
    menu_utils.print_header("Finalize Stale RUNNING Runs")
    threshold_minutes = 60
    stale_count = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='RUNNING'
          AND ended_at_utc IS NULL
          AND (
            STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f')
              < (UTC_TIMESTAMP() - INTERVAL %s MINUTE)
            OR STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')
              < (UTC_TIMESTAMP() - INTERVAL %s MINUTE)
          )
        """,
        (threshold_minutes, threshold_minutes),
    ) or 0

    if stale_count == 0:
        print(status_messages.status("No stale RUNNING rows found.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    print(
        status_messages.status(
            f"Found {stale_count} RUNNING row(s) older than {threshold_minutes} minutes.",
            level="warn",
        )
    )
    if not prompt_utils.prompt_yes_no("Finalize now?", default=False):
        print(status_messages.status("Finalize cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    run_sql(
        """
        UPDATE static_analysis_runs
        SET status='FAILED',
            ended_at_utc=UTC_TIMESTAMP(),
            abort_reason='stale_finalize'
        WHERE status='RUNNING'
          AND ended_at_utc IS NULL
          AND (
            STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f')
              < (UTC_TIMESTAMP() - INTERVAL %s MINUTE)
            OR STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')
              < (UTC_TIMESTAMP() - INTERVAL %s MINUTE)
          )
        """,
        (threshold_minutes, threshold_minutes),
    )
    print(status_messages.status("Stale RUNNING rows finalized.", level="success"))
    prompt_utils.press_enter_to_continue()


def prompt_delete_orphan_permission_snapshots() -> None:
    print()
    menu_utils.print_header("Delete Orphan Permission Audit Snapshots")

    rows = run_sql(
        """
        SELECT snapshot_id, snapshot_key, created_at
        FROM permission_audit_snapshots
        WHERE run_id IS NULL
          AND static_run_id IS NULL
          AND NOT EXISTS (
            SELECT 1
            FROM permission_audit_apps a
            WHERE a.snapshot_id = permission_audit_snapshots.snapshot_id
          )
        ORDER BY created_at DESC
        LIMIT 10
        """,
        fetch="all",
        dictionary=True,
    ) or []
    count = scalar(
        """
        SELECT COUNT(*)
        FROM permission_audit_snapshots
        WHERE run_id IS NULL
          AND static_run_id IS NULL
          AND NOT EXISTS (
            SELECT 1
            FROM permission_audit_apps a
            WHERE a.snapshot_id = permission_audit_snapshots.snapshot_id
          )
        """
    ) or 0

    if count == 0:
        print(status_messages.status("No orphan permission_audit_snapshots found.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    print(status_messages.status(f"Found {count} orphan snapshot(s).", level="warn"))
    if rows:
        table_rows = [
            [
                str(row.get("snapshot_id") or ""),
                str(row.get("snapshot_key") or ""),
                str(row.get("created_at") or ""),
            ]
            for row in rows
        ]
        table_utils.render_table(["snapshot_id", "snapshot_key", "created_at"], table_rows, compact=True)
        print()

    if not prompt_utils.prompt_yes_no("Proceed with delete?", default=False):
        print(status_messages.status("Delete cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    confirmation = prompt_utils.prompt_text(
        "Type DELETE ORPHANS to confirm",
        required=True,
    ).strip()
    if confirmation != "DELETE ORPHANS":
        print(status_messages.status("Confirmation mismatch. Delete cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    started_at = datetime.now(UTC)
    run_sql(
        """
        DELETE FROM permission_audit_snapshots
        WHERE run_id IS NULL
          AND static_run_id IS NULL
          AND NOT EXISTS (
            SELECT 1
            FROM permission_audit_apps a
            WHERE a.snapshot_id = permission_audit_snapshots.snapshot_id
          )
        """,
        fetch=None,
    )
    finished_at = datetime.now(UTC)
    deleted_rows = int(count or 0)
    log_db_op(
        operation="delete_orphan_permission_snapshots",
        started_at=started_at,
        finished_at=finished_at,
        success=True,
        error_text=f"deleted_rows={deleted_rows}",
    )
    print(status_messages.status(f"Deleted {deleted_rows} orphan snapshot(s).", level="success"))
    prompt_utils.press_enter_to_continue()


def prompt_backfill_pcap_metadata() -> None:
    print()
    menu_utils.print_header("Backfill PCAP Metadata")

    rows, count = fetch_pcap_backfill_candidates(limit=25)

    if count == 0:
        print(status_messages.status("No runs require PCAP backfill.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    print(status_messages.status(f"Found {count} run(s) missing PCAP metadata.", level="warn"))
    if rows:
        table_rows = [
            [str(row.get("dynamic_run_id") or ""), str(row.get("evidence_path") or "")]
            for row in rows
        ]
        table_utils.render_table(["dynamic_run_id", "evidence_path"], table_rows, compact=True)
        print()

    if not prompt_utils.prompt_yes_no("Backfill PCAP metadata now?", default=True):
        print(status_messages.status("Backfill cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    updated = 0
    started_at = datetime.now(UTC)
    for row in rows:
        run_id = row.get("dynamic_run_id")
        evidence_path = row.get("evidence_path")
        if not run_id or not evidence_path:
            continue
        pcap_relpath, pcap_sha256, pcap_bytes, pcap_valid = load_pcap_summary_fields(str(evidence_path))
        pcap_validated_at = datetime.now(UTC) if pcap_valid is not None else None
        run_sql(
            """
            UPDATE dynamic_sessions
            SET pcap_relpath = %s,
                pcap_bytes = %s,
                pcap_sha256 = %s,
                pcap_valid = %s,
                pcap_validated_at_utc = %s
            WHERE dynamic_run_id = %s
            """,
            (
                pcap_relpath,
                pcap_bytes,
                pcap_sha256,
                1 if pcap_valid is True else 0 if pcap_valid is False else None,
                pcap_validated_at.strftime("%Y-%m-%d %H:%M:%S") if pcap_validated_at else None,
                run_id,
            ),
            fetch=None,
        )
        updated += 1

    finished_at = datetime.now(UTC)
    log_db_op(
        operation="backfill_pcap_metadata",
        started_at=started_at,
        finished_at=finished_at,
        success=True,
        error_text=f"updated_rows={updated}",
    )
    print(status_messages.status(f"Backfilled PCAP metadata for {updated} run(s).", level="success"))
    prompt_utils.press_enter_to_continue()


def prompt_recompute_network_signal_quality() -> None:
    print()
    menu_utils.print_header("Recompute Network Signal Quality")

    count = fetch_dataset_tier_run_count()

    if count == 0:
        print(status_messages.status("No dataset-tier runs found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print(status_messages.status(f"Dataset runs to update: {count}", level="info"))
    if not prompt_utils.prompt_typed_confirmation(
        "Type RECOMPUTE NETWORK to continue",
        "RECOMPUTE NETWORK",
    ):
        print(status_messages.status("Recompute cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    started_at = datetime.now(UTC)
    recompute_network_signal_quality()
    finished_at = datetime.now(UTC)
    log_db_op(
        operation="recompute_network_signal_quality",
        started_at=started_at,
        finished_at=finished_at,
        success=True,
        error_text=f"updated_rows={int(count)}",
    )
    print(status_messages.status("Network signal quality recomputed.", level="success"))
    prompt_utils.press_enter_to_continue()


__all__ = [
    "run_health_summary",
    "run_health_checks",
    "run_tier1_audit_report",
    "prompt_finalize_stale_runs",
    "prompt_delete_orphan_permission_snapshots",
    "prompt_backfill_pcap_metadata",
    "prompt_recompute_network_signal_quality",
    "prompt_reset_static_data",
]


