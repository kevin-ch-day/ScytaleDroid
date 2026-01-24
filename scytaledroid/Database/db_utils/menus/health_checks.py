"""Data health checks for Database Utilities menu."""

from __future__ import annotations

import textwrap
from typing import Any, Dict, List, Optional, Sequence

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.terminal import get_terminal_width

from .sql_helpers import coerce_datetime, scalar, view_exists
from ..reset_static import (
    HARVEST_TABLES,
    PROTECTED_TABLES,
    STATIC_ANALYSIS_TABLES,
    reset_static_analysis_data,
)


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

        effective_total = scalar(
            """
            SELECT COUNT(*)
            FROM v_strings_effective x
            JOIN static_string_summary s ON s.id = x.summary_id
            WHERE s.session_stamp = %s
            """,
            (session_stamp,),
        )
        if effective_total is not None:
            _print_status_line(
                "ok" if effective_total else "warn",
                "v_strings_effective",
                detail=str(effective_total or 0),
            )

        suppressed_total = scalar(
            """
            SELECT COUNT(*)
            FROM v_doc_policy_drift d
            JOIN static_string_summary s ON s.id = d.summary_id
            WHERE s.session_stamp = %s
            """,
            (session_stamp,),
        )
        if suppressed_total is not None:
            _print_status_line(
                "ok",
                "v_doc_policy_drift",
                detail=str(suppressed_total or 0),
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
    print(status_messages.status("Type 'CLEAN' to delete or press Enter to cancel.", level="warn"))
    confirmation = prompt_utils.prompt_text("Confirm cleanup keyword", required=False)
    if confirmation.strip().upper() != "CLEAN":
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

    print(status_messages.status("Type 'RESET' to proceed or press Enter to cancel.", level="warn"))

    while True:
        confirmation = prompt_utils.prompt_text(
            "Confirm reset keyword",
            required=False,
        )
        normalised = confirmation.strip().upper()
        if not normalised:
            print(status_messages.status("Reset cancelled.", level="warn"))
            prompt_utils.press_enter_to_continue()
            return
        if normalised == "RESET":
            break
        print(status_messages.status("Input not recognised. Type 'RESET' to confirm or press Enter to cancel.", level="warn"))

    outcome = reset_static_analysis_data(include_harvest=include_harvest)

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


__all__ = ["run_health_checks", "prompt_reset_static_data"]


def _print_table_list(title: str, tables: Sequence[str]) -> None:
    if not tables:
        return
    menu_utils.print_section(title)
    _print_wrapped_table_block(list(tables))


def _print_wrapped_table_block(tables: Sequence[str], width: int | None = None) -> None:
    if not tables:
        return
    effective_width = width or min(get_terminal_width(), 96)
    joined = ", ".join(tables)
    wrapped = textwrap.wrap(joined, width=effective_width - 2) or [joined]
    for line in wrapped:
        print(f"  {line}")
