"""Data health checks for Database Utilities menu."""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.DisplayUtils.terminal import get_terminal_width

from .sql_helpers import coerce_datetime, scalar, view_exists
from ..menu_actions import log_db_op
from ..reset_static import (
    HARVEST_TABLES,
    PROTECTED_TABLES,
    STATIC_ANALYSIS_TABLES,
    reset_static_analysis_data,
)

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

    running_total = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='RUNNING' AND ended_at_utc IS NULL
        """
    )
    running_recent = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='RUNNING' AND ended_at_utc IS NULL
          AND COALESCE(
            STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f'),
            STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')
          ) >= (UTC_TIMESTAMP() - INTERVAL 1 DAY)
        """
    )
    ok_recent = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status IN ('COMPLETED','OK')
          AND ended_at_utc >= (UTC_TIMESTAMP() - INTERVAL 1 DAY)
        """
    )
    failed_recent = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='FAILED'
          AND ended_at_utc >= (UTC_TIMESTAMP() - INTERVAL 1 DAY)
        """
    )
    aborted_recent = scalar(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='ABORTED'
          AND ended_at_utc >= (UTC_TIMESTAMP() - INTERVAL 1 DAY)
        """
    )
    menu_utils.print_section("Run status")
    print(f"RUNNING (total)   : {running_total if running_total is not None else '—'}")
    print(f"RUNNING (last 24h): {running_recent if running_recent is not None else '—'}")
    print(f"OK (last 24h)     : {ok_recent if ok_recent is not None else '—'}")
    print(f"FAILED (last 24h) : {failed_recent if failed_recent is not None else '—'}")
    print(f"ABORTED (last 24h): {aborted_recent if aborted_recent is not None else '—'}")

    menu_utils.print_section("Orphan checks")
    orphan_findings = scalar(
        """
        SELECT COUNT(*)
        FROM static_findings f
        LEFT JOIN static_findings_summary s ON s.id = f.summary_id
        WHERE s.id IS NULL
        """
    )
    orphan_samples = scalar(
        """
        SELECT COUNT(*)
        FROM static_string_samples x
        LEFT JOIN static_string_summary s ON s.id = x.summary_id
        WHERE s.id IS NULL
        """
    )
    orphan_audit = scalar(
        """
        SELECT COUNT(*)
        FROM permission_audit_apps a
        LEFT JOIN permission_audit_snapshots s ON s.snapshot_id = a.snapshot_id
        WHERE s.snapshot_id IS NULL
        """
    )
    print(f"orphan_findings        : {orphan_findings if orphan_findings is not None else '—'}")
    print(f"orphan_string_samples  : {orphan_samples if orphan_samples is not None else '—'}")
    print(f"orphan_audit_apps      : {orphan_audit if orphan_audit is not None else '—'}")

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
        print(f"audit_missing_relpath  : {missing_evidence if missing_evidence is not None else '—'}")
        print(f"audit_missing_sha256   : {missing_hash if missing_hash is not None else '—'}")
    else:
        print("audit evidence fields  : not tracked")

    menu_utils.print_section("Governance snapshot")
    gov_headers = scalar("SELECT COUNT(*) FROM permission_governance_snapshots")
    gov_rows = scalar("SELECT COUNT(*) FROM permission_governance_snapshot_rows")
    print(f"snapshots              : {gov_headers if gov_headers is not None else '—'}")
    print(f"rows                   : {gov_rows if gov_rows is not None else '—'}")

    prompt_utils.press_enter_to_continue()


def run_health_checks() -> None:
    print()
    menu_utils.print_header("Data Health Checks")

    latest_run = _fetch_latest_run()
    latest_session = _fetch_latest_session()

    if latest_run is None and latest_session is None:
        print(status_messages.status("No runs or summaries recorded yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    run_id = int(latest_run.get("run_id") or 0) if latest_run else 0
    package = str(
        (latest_run or {}).get("package")
        or (latest_session or {}).get("package_name")
        or "<unknown>"
    )
    ts_value = (latest_run or {}).get("ts")
    ts_dt = coerce_datetime(ts_value)
    session_from_run = (latest_run or {}).get("session_stamp")
    session_stamp = session_from_run or (latest_session or {}).get("session_stamp")

    print(
        "Ingestion — latest session "
        f"(session={session_stamp or 'unknown'})"
    )

    if session_stamp:
        findings_total = scalar(
            "SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp = %s",
            (session_stamp,),
        )
        findings_detail = _fetch_findings_detail(session_stamp)
        _print_status_line(
            "ok" if findings_total else "fail",
            "static_findings_summary",
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
                "static_findings",
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
        if samples_total is not None:
            _print_status_line(
                "ok" if samples_total else "warn",
                "static_string_samples (raw)",
                detail=str(samples_total or 0),
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
    print("Run linkage")
    if latest_run:
        run_label = f"run_id={run_id}, pkg={package}, ts={ts_dt or ts_value}"
        _print_status_line("ok", "runs", detail=run_label)

        buckets_count = scalar("SELECT COUNT(*) FROM buckets WHERE run_id=%s", (run_id,))
        _print_status_line(
            "ok" if buckets_count else "fail",
            "buckets",
            detail=str(buckets_count or 0),
        )

        metrics_rows = _fetch_metrics_summary(run_id)
        if metrics_rows:
            detail = ", ".join(
                f"{row['feature_key']}={row['value_num']}" for row in metrics_rows
            )
            _print_status_line("ok", "metrics", detail=detail)
        else:
            _print_status_line("warn", "metrics", detail="expected keys not present")
    else:
        _print_status_line(
            "warn",
            "runs",
            detail="no rows in runs table; run baseline/full analysis to populate",
        )

    print()
    print("Scoring & coverage")
    _render_scoring_checks()

    print()
    print("Integrity")
    _render_integrity_checks(session_stamp)

    prompt_utils.press_enter_to_continue()


def run_app_identity_audit() -> None:
    """Audit app identity consistency (duplicates, missing version info)."""
    print()
    menu_utils.print_header("App Identity Audit")

    duplicates = run_sql(
        """
        SELECT a.package_name, av.version_code, COUNT(*) AS n
        FROM app_versions av
        JOIN apps a ON a.id = av.app_id
        GROUP BY a.package_name, av.version_code
        HAVING COUNT(*) > 1
        ORDER BY n DESC
        LIMIT 20
        """,
        fetch="all",
        dictionary=True,
    ) or []

    missing_version_code = scalar(
        "SELECT COUNT(*) FROM app_versions WHERE version_code IS NULL"
    )
    missing_version_name = scalar(
        "SELECT COUNT(*) FROM app_versions WHERE version_name IS NULL OR version_name = ''"
    )

    menu_utils.print_section("Missing version fields")
    print(f"version_code missing  : {missing_version_code if missing_version_code is not None else '—'}")
    print(f"version_name missing  : {missing_version_name if missing_version_name is not None else '—'}")

    menu_utils.print_section("Duplicates (package + version_code)")
    if not duplicates:
        print("None detected.")
    else:
        for row in duplicates:
            package = row.get("package_name")
            version_code = row.get("version_code")
            count = row.get("n")
            print(f"{package} v{version_code} -> {count} rows")

    prompt_utils.press_enter_to_continue()


def run_evidence_integrity_check() -> None:
    """Check evidence linkage fields for snapshots."""
    print()
    menu_utils.print_header("Evidence Integrity Check")

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


def _fetch_latest_run() -> Optional[Dict[str, Any]]:
    try:
        return run_sql(
            "SELECT run_id, package, version_name, target_sdk, ts, session_stamp FROM runs ORDER BY run_id DESC LIMIT 1",
            fetch="one",
            dictionary=True,
        )
    except Exception as exc:
        # Fallback to legacy schema without session_stamp
        try:
            row = run_sql(
                "SELECT run_id, package, version_name, target_sdk, ts FROM runs ORDER BY run_id DESC LIMIT 1",
                fetch="one",
                dictionary=True,
            )
            if row is None:
                return None
            row.setdefault("session_stamp", None)
            return row
        except Exception:
            print(status_messages.status(f"Unable to query runs table: {exc}", level="error"))
            return None


def _fetch_latest_session() -> Optional[Dict[str, Any]]:
    try:
        return run_sql(
            """
            SELECT session_stamp, package_name
            FROM static_findings_summary
            ORDER BY created_at DESC
            LIMIT 1
            """,
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None


def _render_scoring_checks() -> None:
    try:
        rows = run_sql(
            """
            SELECT s.snapshot_id, s.apps_total, COUNT(a.audit_id) AS actual
            FROM permission_audit_snapshots s
            LEFT JOIN permission_audit_apps a ON a.snapshot_id = s.snapshot_id
            GROUP BY s.snapshot_id, s.apps_total
            ORDER BY s.snapshot_id DESC
            LIMIT 3
            """,
            fetch="all",
            dictionary=True,
        )
    except Exception as exc:
        print(status_messages.status(f"Unable to query permission_audit tables: {exc}", level="error"))
        return

    if rows:
        snapshot = rows[0]
        snapshot_id = snapshot.get("snapshot_id")
        actual = int(snapshot.get("actual") or 0)
        expected = int(snapshot.get("apps_total") or 0)
        level = "ok" if expected == actual else "warn"
        detail = f"{snapshot_id}: expected {expected}, actual {actual}"
        _print_status_line(level, "permission_audit_snapshots ↔ permission_audit_apps", detail=detail)
    else:
        _print_status_line("warn", "permission audit", detail="no snapshots recorded yet")

    latest_snapshot_id = scalar("SELECT MAX(snapshot_id) FROM permission_audit_snapshots")
    if latest_snapshot_id:
        grade_rows = run_sql(
            """
            SELECT grade, COUNT(*) AS cnt
            FROM permission_audit_apps
            WHERE snapshot_id = %s
            GROUP BY grade
            ORDER BY grade
            """,
            (latest_snapshot_id,),
            fetch="all",
            dictionary=True,
        ) or []
        if grade_rows:
            detail = ", ".join(f"{row.get('grade') or '∅'}:{row.get('cnt')}" for row in grade_rows)
            _print_status_line("ok", "grade distribution", detail=detail)
        else:
            _print_status_line("warn", "grade distribution", detail="no apps linked to latest snapshot")
    else:
        _print_status_line("warn", "grade distribution", detail="no snapshots available")

    optional_tables = {
        "contributors": "wire risk contributors emit",
        "correlations": "wire correlation detector persistence",
        "risk_scores": "optional rollup; populate after scoring contributors",
        "static_permission_risk": "optional per-apk rollup; populate after scoring contributors",
    }
    for table, hint in optional_tables.items():
        count = scalar(f"SELECT COUNT(*) FROM {table}")
        if count:
            level = "ok"
        elif table in {"correlations", "risk_scores"}:
            level = "info"
        else:
            level = "warn"
        detail = f"{count or 0} rows"
        if not count:
            detail += f" — {hint}"
        _print_status_line(level, table, detail=detail)


def _render_integrity_checks(session_stamp: Optional[str]) -> None:
    _print_status_line(
        "warn",
        "latest APK ↔ summary",
        detail="view checks disabled by policy (no DB views)",
    )

    sample_rows = run_sql(
        """
        SELECT s.id AS summary_id, COUNT(x.id) AS samples
        FROM static_findings_summary s
        LEFT JOIN static_string_samples x ON x.summary_id = s.id
        WHERE %s IS NULL OR s.session_stamp = %s
        GROUP BY s.id
        ORDER BY s.created_at DESC
        LIMIT 5
        """,
        (session_stamp, session_stamp),
        fetch="all",
        dictionary=True,
    ) or []
    if sample_rows:
        zero_samples = [row["summary_id"] for row in sample_rows if not row.get("samples")]
        if zero_samples:
            _print_status_line(
                "warn",
                "summary ↔ string samples",
                detail=f"missing samples for summary_id(s) {', '.join(map(str, zero_samples))}",
            )
        else:
            _print_status_line("ok", "summary ↔ string samples", detail=f"{len(sample_rows)} summaries inspected")
    else:
        _print_status_line(
            "warn",
            "summary ↔ string samples",
            detail="no summaries found for recent sessions",
        )


def _fetch_findings_detail(session_stamp: str) -> Optional[str]:
    try:
        row = run_sql(
            """
            SELECT SUM(high) AS high, SUM(med) AS med, SUM(low) AS low, SUM(info) AS info
            FROM static_findings_summary
            WHERE session_stamp = %s
            """,
            (session_stamp,),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None
    if not row:
        return None
    return (
        f"H{row.get('high', 0)}/M{row.get('med', 0)}/"
        f"L{row.get('low', 0)}/I{row.get('info', 0)}"
    )


def _fetch_string_summary_detail(session_stamp: str) -> Optional[str]:
    try:
        row = run_sql(
            """
            SELECT SUM(endpoints) AS endpoints,
                   SUM(http_cleartext) AS http_cleartext,
                   SUM(high_entropy) AS high_entropy
            FROM static_string_summary
            WHERE session_stamp = %s
            """,
            (session_stamp,),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None
    if not row:
        return None
    return (
        f"endpoints={row.get('endpoints', 0)}, "
        f"http={row.get('http_cleartext', 0)}, "
        f"entropy={row.get('high_entropy', 0)}"
    )


def _fetch_metrics_summary(run_id: int) -> Optional[List[Dict[str, Any]]]:
    try:
        rows = run_sql(
            """
            SELECT feature_key, value_num
            FROM metrics
            WHERE run_id = %s
              AND feature_key IN ('network.code_http_hosts', 'exports.total')
            ORDER BY feature_key
            """,
            (run_id,),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return None
    return rows or None


def _print_status_line(level: str, label: str, *, detail: Optional[str] = None) -> None:
    icons = {"ok": "✅", "warn": "⚠️", "fail": "❌"}
    prefix = icons.get(level, "•")
    line = f"  {prefix} {label}"
    if detail:
        line += f" ({detail})"
    print(line)


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
    menu_utils.print_section("Inventory DB health")

    snapshot_headers_total = scalar("SELECT COUNT(*) FROM device_inventory_snapshots") or 0
    inventory_rows_total = scalar("SELECT COUNT(*) FROM device_inventory") or 0
    orphan_headers = scalar(
        """
        SELECT COUNT(*)
        FROM device_inventory_snapshots s
        LEFT JOIN device_inventory i ON i.snapshot_id = s.snapshot_id
        WHERE i.snapshot_id IS NULL
        """
    ) or 0

    latest = run_sql(
        """
        SELECT snapshot_id, package_count
        FROM device_inventory_snapshots
        ORDER BY captured_at DESC
        LIMIT 1
        """,
        fetch="one",
    )
    latest_snapshot_id = int(latest[0]) if latest else 0
    latest_expected = int(latest[1]) if latest else 0
    latest_rows = 0
    latest_is_orphan = False
    if latest_snapshot_id:
        latest_rows = scalar(
            "SELECT COUNT(*) FROM device_inventory WHERE snapshot_id = %s",
            (latest_snapshot_id,),
        ) or 0
        latest_is_orphan = latest_rows == 0

    bad_pkg_count = scalar(
        """
        SELECT COUNT(*)
        FROM device_inventory
        WHERE package_name LIKE '%/%'
           OR package_name LIKE '%=%'
           OR package_name LIKE '%base.apk%'
           OR package_name LIKE '% %'
        """
    ) or 0

    case_variants = scalar(
        """
        SELECT COUNT(*)
        FROM (
            SELECT LOWER(a.package_name) AS pkg_lower,
                   COUNT(DISTINCT a.package_name) AS variants_in_apps,
                   COUNT(DISTINCT i.package_name) AS variants_in_inventory
            FROM apps a
            LEFT JOIN device_inventory i
              ON LOWER(i.package_name) = LOWER(a.package_name)
            GROUP BY LOWER(a.package_name)
            HAVING COUNT(DISTINCT a.package_name) > 1
                OR COUNT(DISTINCT i.package_name) > 1
        ) v
        """
    ) or 0

    vendor_misc_remaining = scalar(
        "SELECT COUNT(*) FROM apps WHERE publisher_key = 'VENDOR_MISC'"
    ) or 0

    label_is_package = scalar(
        """
        SELECT COUNT(*)
        FROM device_inventory
        WHERE snapshot_id = %s
          AND LOWER(CONVERT(app_label USING utf8mb4)) COLLATE utf8mb4_unicode_ci
              = LOWER(CONVERT(package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
        """,
        (latest_snapshot_id,),
    ) if latest_snapshot_id else 0

    label_mismatch = scalar(
        """
        SELECT COUNT(*)
        FROM device_inventory i
        JOIN apps a
          ON LOWER(CONVERT(i.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
             = LOWER(CONVERT(a.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
        WHERE i.snapshot_id = %s
          AND i.app_label IS NOT NULL
          AND i.app_label <> ''
          AND LOWER(CONVERT(i.app_label USING utf8mb4)) COLLATE utf8mb4_unicode_ci
              <> LOWER(CONVERT(a.display_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
        """,
        (latest_snapshot_id,),
    ) if latest_snapshot_id else 0

    if snapshot_headers_total:
        legacy_orphans = orphan_headers - (1 if latest_is_orphan else 0)
        if latest_snapshot_id and latest_rows == latest_expected and latest_expected:
            level = "ok" if orphan_headers == 0 else "warn"
        else:
            level = "fail" if orphan_headers else "warn"
        _print_status_line(
            level,
            "inventory snapshots",
            detail=(
                f"headers={snapshot_headers_total} orphaned={orphan_headers} "
                f"legacy={max(legacy_orphans, 0)}"
            ),
        )
    else:
        _print_status_line("warn", "inventory snapshots", detail="no snapshots recorded")

    if latest_snapshot_id:
        level = "ok" if latest_rows == latest_expected and latest_expected else "fail"
        _print_status_line(
            level,
            "latest snapshot row count",
            detail=f"id={latest_snapshot_id} rows={latest_rows} expected={latest_expected}",
        )
    else:
        _print_status_line("warn", "latest snapshot", detail="no snapshot headers recorded")

    _print_status_line(
        "ok" if bad_pkg_count == 0 else "warn",
        "suspicious package_name",
        detail=str(bad_pkg_count),
    )

    _print_status_line(
        "ok" if case_variants == 0 else "warn",
        "case drift (apps ↔ inventory)",
        detail=str(case_variants),
    )

    _print_status_line(
        "ok" if vendor_misc_remaining == 0 else "warn",
        "vendor_misc publishers",
        detail=str(vendor_misc_remaining),
    )

    if latest_snapshot_id:
        _print_status_line(
            "ok" if label_is_package == 0 else "warn",
            "inventory labels equal package",
            detail=str(label_is_package),
        )
        _print_status_line(
            "ok" if label_mismatch == 0 else "warn",
            "inventory label mismatch vs apps",
            detail=str(label_mismatch),
        )


def prompt_reset_static_data() -> None:
    print()
    menu_utils.print_header("Reset Static Analysis Data")

    menu_utils.print_section("Overview")
    print("Use this tool to purge derived static-analysis data before a verification run.")
    print(status_messages.status("Protected catalog tables are always retained.", level="info"))
    print()

    _print_table_list("Protected catalog tables", PROTECTED_TABLES)
    _print_table_list("Static-analysis tables scheduled", STATIC_ANALYSIS_TABLES)

    include_harvest = prompt_utils.prompt_yes_no(
        "Also clear harvested APK inventory (requires re-pull)?",
        default=False,
    )
    if include_harvest:
        _print_table_list("Harvest tables scheduled", HARVEST_TABLES)

    table_counts = _count_tables(STATIC_ANALYSIS_TABLES)
    _print_table_counts("Static-analysis row counts", table_counts)
    if include_harvest:
        harvest_counts = _count_tables(HARVEST_TABLES)
        _print_table_counts("Harvest row counts", harvest_counts)

    if not prompt_utils.prompt_yes_no("Proceed?", default=False):
        print(status_messages.status("Reset cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    confirmation = prompt_utils.prompt_text(
        "Type RESET STATIC to confirm",
        required=True,
    ).strip()
    if confirmation != "RESET STATIC":
        print(status_messages.status("Confirmation mismatch. Reset cancelled.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    started_at = datetime.now(timezone.utc)
    outcome = reset_static_analysis_data(include_harvest=include_harvest)
    finished_at = datetime.now(timezone.utc)
    log_db_op(
        operation="reset_static_analysis",
        started_at=started_at,
        finished_at=finished_at,
        success=True,
        error_text=None,
    )

    menu_utils.print_section("Reset summary")
    width = min(get_terminal_width(), 96)
    print(
        status_messages.status(
            "Reset uses TRUNCATE when permitted; falls back to DELETE when TRUNCATE is denied.",
            level="info",
        )
    )

    if outcome.truncated:
        print(status_messages.status(f"Cleared {len(outcome.truncated)} table(s) via TRUNCATE.", level="success"))
        _print_wrapped_table_block(outcome.truncated, width)
    if getattr(outcome, "cleared", None):
        print(status_messages.status(f"Cleared {len(outcome.cleared)} table(s) via DELETE.", level="success"))
        _print_wrapped_table_block(outcome.cleared, width)
    if not outcome.truncated and not getattr(outcome, "cleared", None):
        print(status_messages.status("No tables were truncated.", level="warn"))

    if outcome.skipped_protected:
        print(status_messages.status(f"Skipped {len(outcome.skipped_protected)} protected table(s).", level="info"))
        _print_wrapped_table_block(outcome.skipped_protected, width)

    if outcome.skipped_missing:
        print(status_messages.status(f"{len(outcome.skipped_missing)} table(s) not found in this database.", level="warn"))
        _print_wrapped_table_block(outcome.skipped_missing, width)

    if outcome.failed:
        print(status_messages.status(f"Failed to truncate {len(outcome.failed)} table(s).", level="error"))
        for table, reason in outcome.failed:
            print(f"  • {table}")
            wrapped = textwrap.wrap(reason, width=width - 6) or [reason]
            for line in wrapped:
                print(f"      {line}")

    print()
    prompt_utils.press_enter_to_continue()


def run_tier1_audit_report() -> None:
    print()
    menu_utils.print_header("Tier-1 Audit Report")

    schema_version = diagnostics.get_schema_version() or "<unknown>"
    print(f"Schema version : {schema_version}")
    print()

    required_tables = (
        "dynamic_sessions",
        "dynamic_telemetry_process",
        "dynamic_telemetry_network",
        "dynamic_session_issues",
    )
    missing_tables = [name for name in required_tables if not _table_exists(name)]
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
        "Tier-1 QA-pass runs",
        detail=str(tier1_ready or 0),
    )

    evidence_missing = _count_evidence_integrity_issues()
    _print_status_line(
        "ok" if evidence_missing == 0 else "warn",
        "evidence integrity (missing fields)",
        detail=str(evidence_missing),
    )
    if evidence_missing:
        if prompt_utils.prompt_yes_no("Show missing evidence details?", default=False):
            rows = _fetch_evidence_integrity_issues(limit=25)
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

    pcap_counts = _fetch_pcap_audit_counts()
    if pcap_counts:
        linked = pcap_counts.get("linked", 0)
        exists = pcap_counts.get("exists", 0)
        valid = pcap_counts.get("valid", 0)
        detail = f"linked={linked} exists={exists} valid={valid}"
        level = "ok" if linked and valid else "warn"
        _print_status_line(level, "PCAP linkage/validity", detail=detail)

    netstats_summary = _fetch_netstats_missing_summary()
    if netstats_summary:
        print(status_messages.status("Tier-1 netstats missing summary:", level="info"))
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

    started_at = datetime.now(timezone.utc)
    run_sql(
        """
        DELETE FROM permission_audit_snapshots
        WHERE run_id IS NULL
          AND static_run_id IS NULL
        """,
        fetch=None,
    )
    finished_at = datetime.now(timezone.utc)
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

    rows = run_sql(
        """
        SELECT dynamic_run_id, evidence_path
        FROM dynamic_sessions
        WHERE pcap_relpath IS NULL
          AND evidence_path IS NOT NULL
        ORDER BY started_at_utc DESC
        LIMIT 25
        """,
        fetch="all",
        dictionary=True,
    ) or []
    count = scalar(
        """
        SELECT COUNT(*)
        FROM dynamic_sessions
        WHERE pcap_relpath IS NULL
          AND evidence_path IS NOT NULL
        """
    ) or 0

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
    started_at = datetime.now(timezone.utc)
    for row in rows:
        run_id = row.get("dynamic_run_id")
        evidence_path = row.get("evidence_path")
        if not run_id or not evidence_path:
            continue
        summary_path = Path(str(evidence_path)) / "analysis" / "summary.json"
        if not summary_path.exists():
            continue
        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        capture = payload.get("capture") or {}
        evidence = payload.get("evidence") or []
        pcap_relpath = None
        pcap_sha256 = None
        pcap_bytes = None
        for entry in evidence:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") in {"pcapdroid_capture", "network_capture", "proxy_capture"}:
                pcap_relpath = entry.get("relative_path")
                pcap_sha256 = entry.get("sha256")
                pcap_bytes = entry.get("size_bytes")
                break
        if pcap_bytes is None and isinstance(capture, dict):
            pcap_bytes = capture.get("pcap_size_bytes")
        pcap_valid = capture.get("pcap_valid")
        pcap_validated_at = datetime.now(timezone.utc) if pcap_valid is not None else None
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

    finished_at = datetime.now(timezone.utc)
    log_db_op(
        operation="backfill_pcap_metadata",
        started_at=started_at,
        finished_at=finished_at,
        success=True,
        error_text=f"updated_rows={updated}",
    )
    print(status_messages.status(f"Backfilled PCAP metadata for {updated} run(s).", level="success"))
    prompt_utils.press_enter_to_continue()


__all__ = [
    "run_health_summary",
    "run_health_checks",
    "run_tier1_audit_report",
    "prompt_finalize_stale_runs",
    "prompt_delete_orphan_permission_snapshots",
    "prompt_backfill_pcap_metadata",
    "prompt_reset_static_data",
]


def _print_table_list(title: str, tables: Sequence[str]) -> None:
    if not tables:
        return
    menu_utils.print_section(title)
    _print_wrapped_table_block(list(tables))


def _count_evidence_integrity_issues() -> int:
    if _column_exists("permission_audit_snapshots", "evidence_relpath"):
        missing_relpath = scalar(
            """
            SELECT COUNT(*)
            FROM permission_audit_snapshots
            WHERE evidence_relpath IS NULL OR evidence_relpath = ''
            """
        ) or 0
        missing_hash = scalar(
            """
            SELECT COUNT(*)
            FROM permission_audit_snapshots
            WHERE evidence_sha256 IS NULL OR evidence_sha256 = ''
            """
        ) or 0
        return int(missing_relpath) + int(missing_hash)
    return 0


def _fetch_evidence_integrity_issues(limit: int = 25) -> list[dict[str, object]]:
    rows = run_sql(
        """
        SELECT snapshot_id, snapshot_key, run_id, static_run_id,
               (evidence_relpath IS NULL OR evidence_relpath='') AS missing_relpath,
               (evidence_sha256 IS NULL OR evidence_sha256='') AS missing_sha256
        FROM permission_audit_snapshots
        WHERE (evidence_relpath IS NULL OR evidence_relpath='')
           OR (evidence_sha256 IS NULL OR evidence_sha256='')
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (limit,),
        fetch="all",
        dictionary=True,
    )
    return rows or []


def _fetch_netstats_missing_summary() -> list[dict[str, object]]:
    rows = run_sql(
        """
        SELECT
          package_name,
          COUNT(*) AS run_count,
          SUM(COALESCE(netstats_missing_rows,0)) AS total_missing,
          MAX(COALESCE(netstats_missing_rows,0)) AS max_missing,
          SUM(COALESCE(netstats_rows,0)) AS total_rows
        FROM dynamic_sessions
        WHERE tier='dataset'
        GROUP BY package_name
        ORDER BY total_missing DESC
        """,
        fetch="all",
        dictionary=True,
    )
    summary: list[dict[str, object]] = []
    for row in rows or []:
        total_missing = float(row.get("total_missing") or 0)
        total_rows = float(row.get("total_rows") or 0)
        missing_pct = None
        if total_rows > 0:
            missing_pct = total_missing / total_rows
        summary.append(
            {
                "package_name": row.get("package_name"),
                "run_count": row.get("run_count"),
                "total_missing": row.get("total_missing"),
                "max_missing": row.get("max_missing"),
                "missing_pct": f"{missing_pct:.1%}" if missing_pct is not None else "n/a",
                "missing_pct_value": missing_pct or 0.0,
            }
        )
    return summary


def _fetch_pcap_audit_counts() -> dict[str, int]:
    linked_rows = run_sql(
        """
        SELECT dynamic_run_id, evidence_path, pcap_relpath, pcap_valid
        FROM dynamic_sessions
        WHERE tier='dataset'
          AND pcap_relpath IS NOT NULL
        """,
        fetch="all",
        dictionary=True,
    ) or []
    linked = len(linked_rows)
    exists = 0
    valid = 0
    for row in linked_rows:
        if row.get("pcap_valid") == 1:
            valid += 1
        evidence_path = row.get("evidence_path")
        relpath = row.get("pcap_relpath")
        if not evidence_path or not relpath:
            continue
        try:
            pcap_path = Path(str(evidence_path)) / str(relpath)
            if pcap_path.exists():
                exists += 1
        except Exception:
            continue
    return {"linked": linked, "exists": exists, "valid": valid}


def _count_tables(table_names: Sequence[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in table_names:
        try:
            count = scalar(f"SELECT COUNT(*) FROM {table}") or 0
        except Exception:
            count = 0
        counts[table] = int(count)
    return counts


def _print_table_counts(title: str, counts: dict[str, int]) -> None:
    menu_utils.print_section(title)
    if not counts:
        print("  (none)")
        return
    rows = [[name, str(count)] for name, count in counts.items()]
    table_utils.render_table(["Table", "Rows"], rows)


def _table_exists(table: str) -> bool:
    try:
        row = run_sql(
            """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_name = %s
            """,
            (table,),
            fetch="one",
        )
    except Exception:
        return False
    return bool(row and row[0])


def _print_wrapped_table_block(tables: Sequence[str], width: int | None = None) -> None:
    if not tables:
        return
    effective_width = width or min(get_terminal_width(), 96)
    joined = ", ".join(tables)
    wrapped = textwrap.wrap(joined, width=effective_width - 2) or [joined]
    for line in wrapped:
        print(f"  {line}")
