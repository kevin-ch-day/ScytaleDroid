"""Curated database queries to verify static-analysis persistence."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import run_sql
from scytaledroid.Database.db_scripts.static_run_audit import collect_static_run_counts
from scytaledroid.Database.summary_surfaces import static_dynamic_summary_cache_status
from scytaledroid.StaticAnalysis.cli.persistence.reports.masvs_summary_report import (
    fetch_db_masvs_summary_static_many,
    fetch_masvs_matrix,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from .sql_helpers import coerce_datetime


def run_query_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Curated Read-only Queries")
        menu_utils.print_hint(
            "Inspect persisted static summaries and harvested artifacts."
        )
        menu_utils.print_section("Actions")

        options: Sequence[tuple[str, str]] = (
            ("1", "Active static session"),
            ("2", "Latest session snapshot"),
            ("3", "Session table counts"),
            ("4", "Canonical runs by package"),
            ("5", "Harvest artifacts by package"),
            ("6", "Package-name collation audit"),
            ("7", "Latest static risk surfaces"),
            ("8", "Latest static finding surfaces"),
            ("9", "Summary cache status"),
            ("10", "Harvested version gaps"),
            ("11", "Interrupted permission partials"),
        )
        spec = menu_utils.MenuSpec(
            items=options,
            show_exit=True,
            exit_label="Back",
            padding=False,
            show_descriptions=False,
        )
        menu_utils.render_menu(spec)
        choice = prompt_utils.get_choice(menu_utils.selectable_keys(options, include_exit=True))

        if choice == "1":
            show_active_static_session_status()
        elif choice == "2":
            show_latest_session()
        elif choice == "3":
            prompt_session_counts()
        elif choice == "4":
            prompt_runs_for_package()
        elif choice == "5":
            prompt_harvest_for_package()
        elif choice == "6":
            show_package_collation_audit()
        elif choice == "7":
            prompt_latest_static_risk_surfaces()
        elif choice == "8":
            prompt_latest_static_finding_surfaces()
        elif choice == "9":
            show_summary_cache_status()
        elif choice == "10":
            show_harvested_version_gaps()
        elif choice == "11":
            show_interrupted_permission_partials()
        elif choice == "0":
            break


def show_active_static_session_status() -> None:
    print()
    menu_utils.print_section("Active static session")
    session = _run_read_only(
        """
        SELECT
               session_stamp,
               COUNT(*) AS total_runs,
               SUM(CASE WHEN UPPER(COALESCE(status, '')) = 'STARTED' THEN 1 ELSE 0 END) AS started_runs,
               SUM(CASE WHEN UPPER(COALESCE(status, '')) = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_runs,
               SUM(CASE WHEN UPPER(COALESCE(status, '')) = 'FAILED' THEN 1 ELSE 0 END) AS failed_runs,
               MIN(created_at) AS started_at,
               MAX(created_at) AS latest_at
        FROM static_analysis_runs
        WHERE UPPER(COALESCE(status, '')) = 'STARTED'
        GROUP BY session_stamp
        ORDER BY MAX(created_at) DESC
        LIMIT 1
        """,
        fetch="one",
        dictionary=True,
    )
    if not session:
        print(status_messages.status("No active static session.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    session_stamp = str(session.get("session_stamp") or "").strip()
    archive_count = _archive_report_count(session_stamp)
    downstream = _session_downstream_counts(session_stamp)
    menu_utils.print_metrics(
        [
            ("Session", session_stamp or "—"),
            ("Started", session.get("started_runs") or 0),
            ("Completed", session.get("completed_runs") or 0),
            ("Failed", session.get("failed_runs") or 0),
            ("Archive reports", archive_count),
            ("Since", coerce_datetime(session.get("started_at")) or session.get("started_at") or "—"),
        ]
    )
    print()
    menu_utils.print_metrics(
        [
            ("Session links", downstream["session_links"]),
            ("Findings summary", downstream["findings_summary"]),
            ("String summary", downstream["string_summary"]),
        ]
    )
    prompt_utils.press_enter_to_continue()


def show_latest_session() -> None:
    print()
    menu_utils.print_section("Latest session snapshot")
    session = _run_read_only(
        """
        SELECT
               sar.session_stamp,
               sar.id AS static_run_id,
               a.package_name,
               sar.status,
               sar.created_at
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        ORDER BY sar.id DESC
        LIMIT 1
        """,
        fetch="one",
        dictionary=True,
    )
    if not session:
        print(status_messages.status("No static findings recorded yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    session_stamp = session["session_stamp"]
    created_at = coerce_datetime(session.get("created_at"))
    package = session.get("package_name")
    menu_utils.print_metrics(
        [
            ("Session stamp", session_stamp),
            ("Static run", session.get("static_run_id") or "—"),
            ("Package", package or "—"),
            ("Status", session.get("status") or "—"),
            ("Created at", created_at or session.get("created_at")),
        ]
    )
    print()

    _print_session_counts(session_stamp)
    prompt_utils.press_enter_to_continue()


def prompt_session_counts() -> None:
    session_stamp = prompt_utils.prompt_text(
        "Session stamp (leave blank for latest)",
        required=False,
    ).strip()
    if not session_stamp:
        session_stamp = _latest_session_stamp()
        if not session_stamp:
            print(status_messages.status("No sessions found.", level="warn"))
            prompt_utils.press_enter_to_continue()
            return

    print()
    menu_utils.print_section(f"Session counts — {session_stamp}")
    _print_session_counts(session_stamp)
    prompt_utils.press_enter_to_continue()


def prompt_runs_for_package() -> None:
    package = prompt_utils.prompt_text("Package name", required=False).strip()
    if not package:
        print(status_messages.status("Package name is required.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    rows = _run_read_only(
        """
        SELECT
               sar.id AS static_run_id,
               sar.session_stamp,
               sar.session_label,
               av.version_name,
               av.version_code,
               sar.profile,
               sar.status,
               sar.created_at,
               (
                   SELECT COUNT(*)
                   FROM static_analysis_findings sf
                   WHERE sf.run_id = sar.id
               ) AS findings_total,
               sar.is_canonical
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        WHERE a.package_name = %s
        ORDER BY sar.id DESC
        LIMIT 20
        """,
        (package,),
        fetch="all",
        dictionary=True,
    )

    print()
    menu_utils.print_section(f"Canonical static runs for {package}")
    if not rows:
        print(status_messages.status("No runs found for package.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    table_rows: list[list[str]] = []
    for row in rows:
        table_rows.append(
            [
                str(row.get("static_run_id") or "—"),
                row.get("status") or "—",
                str(coerce_datetime(row.get("created_at")) or row.get("created_at") or "—"),
                "yes" if int(row.get("is_canonical") or 0) else "no",
            ]
        )
    headers = ["Static", "Status", "Created", "Canon"]
    table_utils.render_table(headers, table_rows)
    print()
    print("Per-run details")
    print("---------------")
    for row in rows:
        static_run_id = row.get("static_run_id") or "—"
        print(f"static={static_run_id} status={row.get('status') or '—'}")
        print(
            "  "
            f"session={row.get('session_stamp') or '—'} "
            f"label={row.get('session_label') or '—'}"
        )
        print(
            "  "
            f"version={row.get('version_name') or '—'} ({row.get('version_code') or '—'}) "
            f"profile={row.get('profile') or '—'} canon={'yes' if int(row.get('is_canonical') or 0) else 'no'}"
        )
        print(
            "  "
            f"created={coerce_datetime(row.get('created_at')) or row.get('created_at') or '—'} "
            f"findings={row.get('findings_total') or 0}"
        )
    prompt_utils.press_enter_to_continue()


def prompt_harvest_for_package() -> None:
    package = prompt_utils.prompt_text("Package name", required=False).strip()
    if not package:
        print(status_messages.status("Package name is required.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    rows = _run_read_only(
        """
        SELECT apk_id,
               file_name,
               version_name,
               version_code,
               sha256,
               harvested_at
        FROM android_apk_repository
        WHERE package_name = %s
        ORDER BY harvested_at DESC
        LIMIT 20
        """,
        (package,),
        fetch="all",
        dictionary=True,
    )

    print()
    menu_utils.print_section(f"Harvested APKs for {package}")
    if not rows:
        print(status_messages.status("No harvested artifacts found for package.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    table_rows: list[list[str]] = []
    for row in rows:
        table_rows.append(
            [
                str(row["apk_id"]),
                row.get("file_name") or "—",
                row.get("version_name") or "—",
                str(row.get("version_code") or "—"),
                (row.get("sha256") or "—")[:16],
                str(coerce_datetime(row.get("harvested_at")) or row.get("harvested_at") or "—"),
            ]
        )
    headers = ["APK ID", "File", "Version", "Code", "SHA256 (16)", "Harvested"]
    table_utils.render_table(headers, table_rows)
    prompt_utils.press_enter_to_continue()


def show_summary_cache_status() -> None:
    print()
    menu_utils.print_section("Static/Dynamic Summary Cache")
    rows, materialized_at = static_dynamic_summary_cache_status(runner=run_sql)
    if rows is None:
        print(status_messages.status("Materialized summary cache table not present yet.", level="warn"))
    else:
        menu_utils.print_metrics(
            [
                ("Rows", rows),
                ("Last materialized", materialized_at or "—"),
            ]
        )
    prompt_utils.press_enter_to_continue()


def show_harvested_version_gaps() -> None:
    rows = _run_read_only(
        """
        SELECT
               a.package_name,
               COUNT(*) AS missing_pairs
        FROM (
            SELECT DISTINCT r.app_id, r.version_code
            FROM android_apk_repository r
            WHERE r.app_id IS NOT NULL
              AND r.version_code IS NOT NULL
              AND r.version_code <> ''
              AND r.version_code REGEXP '^[0-9]+$'
        ) repo_versions
        JOIN apps a ON a.id = repo_versions.app_id
        LEFT JOIN app_versions av
          ON av.app_id = repo_versions.app_id
         AND av.version_code = CAST(repo_versions.version_code AS UNSIGNED)
        WHERE av.id IS NULL
        GROUP BY a.package_name
        ORDER BY missing_pairs DESC, a.package_name
        LIMIT 25
        """,
        fetch="all",
        dictionary=True,
    )
    total = _run_read_only(
        """
        SELECT COUNT(*)
        FROM (
            SELECT DISTINCT r.app_id, r.version_code
            FROM android_apk_repository r
            WHERE r.app_id IS NOT NULL
              AND r.version_code IS NOT NULL
              AND r.version_code <> ''
              AND r.version_code REGEXP '^[0-9]+$'
        ) repo_versions
        LEFT JOIN app_versions av
          ON av.app_id = repo_versions.app_id
         AND av.version_code = CAST(repo_versions.version_code AS UNSIGNED)
        WHERE av.id IS NULL
        """,
        fetch="one",
    )
    print()
    menu_utils.print_section("Harvested Version Gaps")
    menu_utils.print_metrics([("Missing app_version pairs", int((total or [0])[0] or 0))])
    print()
    if not rows:
        print(status_messages.status("No harvested version gaps detected.", level="success"))
        prompt_utils.press_enter_to_continue()
        return
    table_utils.render_table(
        ["Package", "Missing Pairs"],
        [[str(row.get("package_name") or "—"), str(row.get("missing_pairs") or 0)] for row in rows],
    )
    prompt_utils.press_enter_to_continue()


def show_interrupted_permission_partials() -> None:
    rows = _run_read_only(
        """
        SELECT
               sar.id AS static_run_id,
               sar.session_stamp,
               a.package_name,
               sar.status,
               (
                   SELECT COUNT(*)
                   FROM static_permission_matrix spm
                   WHERE spm.run_id = sar.id
               ) AS matrix_rows
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        WHERE UPPER(COALESCE(sar.status, '')) IN ('FAILED', 'ABORTED')
          AND EXISTS (SELECT 1 FROM static_permission_matrix spm WHERE spm.run_id = sar.id)
          AND NOT EXISTS (SELECT 1 FROM permission_audit_snapshots pas WHERE pas.static_run_id = sar.id)
        ORDER BY sar.id DESC
        LIMIT 25
        """,
        fetch="all",
        dictionary=True,
    )
    print()
    menu_utils.print_section("Interrupted Permission Partials")
    if not rows:
        print(status_messages.status("No interrupted partial-permission runs detected.", level="success"))
        prompt_utils.press_enter_to_continue()
        return
    table_utils.render_table(
        ["Static", "Session", "Package", "Status", "Matrix"],
        [
            [
                str(row.get("static_run_id") or "—"),
                str(row.get("session_stamp") or "—"),
                str(row.get("package_name") or "—"),
                str(row.get("status") or "—"),
                str(row.get("matrix_rows") or 0),
            ]
            for row in rows
        ],
    )
    prompt_utils.press_enter_to_continue()


def show_package_collation_audit() -> None:
    rows = _run_read_only(
        """
        SELECT table_name, column_name, character_set_name, collation_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND column_name IN ('package_name', 'package', 'package_name_lc')
        ORDER BY table_name, column_name
        """,
        fetch="all",
        dictionary=True,
    )

    print()
    menu_utils.print_section("Package-name collation audit")
    if not rows:
        print(status_messages.status("No package-like columns found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    signature_counts: dict[str, int] = {}
    table_rows: list[list[str]] = []
    for row in rows:
        charset = str(row.get("character_set_name") or "—")
        collation = str(row.get("collation_name") or "—")
        signature = f"{charset}/{collation}"
        signature_counts[signature] = signature_counts.get(signature, 0) + 1
        table_rows.append(
            [
                str(row.get("table_name") or "—"),
                str(row.get("column_name") or "—"),
                charset,
                collation,
            ]
        )

    menu_utils.print_metrics(
        [
            ("Columns", str(len(rows))),
            ("Distinct signatures", str(len(signature_counts))),
            ("Target", "utf8mb4/utf8mb4_unicode_ci"),
        ]
    )
    print()
    headers = ["Table", "Column", "Charset", "Collation"]
    table_utils.render_table(headers, table_rows)
    print()
    print("Signature mix")
    print("-------------")
    for signature, count in sorted(signature_counts.items(), key=lambda item: (-item[1], item[0])):
        print(f"{signature}: {count}")
    prompt_utils.press_enter_to_continue()


def prompt_latest_static_risk_surfaces() -> None:
    package = prompt_utils.prompt_text("Package name", required=False).strip()
    if not package:
        print(status_messages.status("Package name is required.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    row = _run_read_only(
        """
        SELECT *
        FROM vw_static_risk_surfaces_latest
        WHERE package_name = %s
        """,
        (package,),
        fetch="one",
        dictionary=True,
    )

    print()
    menu_utils.print_section(f"Latest static risk surfaces — {package}")
    if not row:
        print(status_messages.status("No latest static risk surface row found for package.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    menu_utils.print_metrics(
        [
            ("Static run", str(row.get("static_run_id") or "—")),
            ("Session", str(row.get("session_stamp") or "—")),
            ("Version", f"{row.get('version_name') or '—'} ({row.get('version_code') or '—'})"),
        ]
    )
    print()
    print("Permission run score")
    print("--------------------")
    print(
        f"surface={row.get('permission_run_surface') or '—'} "
        f"score={row.get('permission_run_score') or '—'} "
        f"grade={row.get('permission_run_grade') or '—'} "
        f"(D={row.get('permission_run_dangerous_count') or 0} "
        f"S={row.get('permission_run_signature_count') or 0} "
        f"O={row.get('permission_run_vendor_count') or 0})"
    )
    print()
    print("Permission audit score")
    print("----------------------")
    print(
        f"surface={row.get('permission_audit_surface') or '—'} "
        f"raw={row.get('permission_audit_score_raw') or '—'} "
        f"capped={row.get('permission_audit_score_capped') or '—'} "
        f"grade={row.get('permission_audit_grade') or '—'} "
        f"(D={row.get('permission_audit_dangerous_count') or 0} "
        f"S={row.get('permission_audit_signature_count') or 0} "
        f"O={row.get('permission_audit_vendor_count') or 0})"
    )
    print()
    print("Composite static score contract")
    print("-------------------------------")
    print(
        f"surface={row.get('composite_static_surface') or '—'} "
        f"state={row.get('composite_static_surface_state') or '—'}"
    )
    prompt_utils.press_enter_to_continue()


def prompt_latest_static_finding_surfaces() -> None:
    package = prompt_utils.prompt_text("Package name", required=False).strip()
    if not package:
        print(status_messages.status("Package name is required.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    row = _run_read_only(
        """
        SELECT *
        FROM vw_static_finding_surfaces_latest
        WHERE package_name = %s
        """,
        (package,),
        fetch="one",
        dictionary=True,
    )

    print()
    menu_utils.print_section(f"Latest static finding surfaces — {package}")
    if not row:
        print(status_messages.status("No latest static finding surface row found for package.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    menu_utils.print_metrics(
        [
            ("Static run", str(row.get("static_run_id") or "—")),
            ("Session", str(row.get("session_stamp") or "—")),
            ("Version", f"{row.get('version_name') or '—'} ({row.get('version_code') or '—'})"),
        ]
    )
    print()
    print("Canonical findings")
    print("------------------")
    print(
        f"surface={row.get('canonical_surface') or '—'} "
        f"total={row.get('canonical_findings_total') or 0} "
        f"H={row.get('canonical_high') or 0} "
        f"M={row.get('canonical_med') or 0} "
        f"L={row.get('canonical_low') or 0} "
        f"I={row.get('canonical_info') or 0}"
    )
    print()
    print("Legacy summary counts")
    print("---------------------")
    print(
        f"surface={row.get('summary_surface') or '—'} "
        f"H={row.get('summary_high') or 0} "
        f"M={row.get('summary_med') or 0} "
        f"L={row.get('summary_low') or 0} "
        f"I={row.get('summary_info') or 0}"
    )
    print()
    print("Baseline detail surface")
    print("-----------------------")
    print(
        f"surface={row.get('baseline_surface') or '—'} "
        f"role={row.get('baseline_surface_role') or '—'} "
        f"rows={row.get('baseline_detail_rows') or 0}"
    )
    prompt_utils.press_enter_to_continue()


def _print_session_counts(session_stamp: str) -> None:
    audit = collect_static_run_counts(session_stamp=session_stamp)
    if not audit:
        print(status_messages.status("No matching session found.", level="warn"))
        return

    menu_utils.print_metrics(
        [
            ("Static run id", audit.static_run_id),
            ("Run id", audit.run_id or "—"),
            ("Scope label", audit.scope_label or "—"),
        ]
    )
    print()

    table_rows: list[list[str]] = []
    for table, (count, status) in audit.counts.items():
        table_rows.append([table, str(count) if count is not None else "—", status])

    table_utils.render_table(["Table", "Rows", "Status"], table_rows)


def _archive_report_count(session_stamp: str) -> int:
    if not session_stamp:
        return 0
    archive_dir = Path(app_config.DATA_DIR) / "static_analysis" / "reports" / "archive" / session_stamp
    try:
        return sum(1 for path in archive_dir.glob("*.json") if path.is_file())
    except OSError:
        return 0


def _session_downstream_counts(session_stamp: str) -> dict[str, int]:
    counts = {
        "session_links": 0,
        "legacy_risk": 0,
        "legacy_runs": 0,
        "findings_summary": 0,
        "string_summary": 0,
    }
    if not session_stamp:
        return counts

    queries = {
        "session_links": "SELECT COUNT(*) FROM static_session_run_links WHERE session_stamp=%s",
        "legacy_risk": "SELECT COUNT(*) FROM risk_scores WHERE session_stamp=%s",
        "legacy_runs": "SELECT COUNT(*) FROM runs WHERE session_stamp=%s",
        "findings_summary": "SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp=%s",
        "string_summary": "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp=%s",
    }
    for key, sql in queries.items():
        row = _run_read_only(sql, (session_stamp,), fetch="one")
        if row:
            counts[key] = int(row[0] or 0)
    return counts


def prompt_masvs_by_package() -> None:
    print()
    menu_utils.print_section("Verify MASVS persistence")
    try:
        latest_runs = _run_read_only(
            """
            SELECT package, MAX(run_id) AS run_id
            FROM runs
            GROUP BY package
            ORDER BY MAX(run_id) DESC
            LIMIT 10
            """,
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        latest_runs = []

    default_package = latest_runs[0]["package"] if latest_runs else ""
    if latest_runs:
        print("Recent packages:")
        for entry in latest_runs:
            print(f"  - {entry['package']} (run_id={entry['run_id']})")
        print()

    package = prompt_utils.prompt_text(
        "Package name (blank for latest)",
        default=default_package,
        required=False,
    ).strip()
    if not package:
        package = default_package
    if not package:
        print(status_messages.status("No package provided and no runs found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        run_row = _run_read_only(
            """
            SELECT
              sar.id AS static_run_id,
              sar.session_label,
              sar.created_at,
              a.package_name
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE a.package_name COLLATE utf8mb4_unicode_ci = %s COLLATE utf8mb4_unicode_ci
            ORDER BY sar.id DESC
            LIMIT 1
            """,
            (package,),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        run_row = None
    if not run_row:
        print(status_messages.status(f"No canonical static runs recorded for package '{package}'.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    static_run_id = int(run_row.get("static_run_id") or 0)
    result = fetch_db_masvs_summary_static_many([static_run_id])
    if result is None:
        print(
            status_messages.status(
                f"No MASVS-tagged canonical findings for package '{package}' (static_run_id={static_run_id}).",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return
    _resolved_id, rows = result

    table_rows: list[list[str]] = []
    total_controls = 0
    for row in rows:
        area = str(row.get("area") or "").upper() or "UNKNOWN"
        high = int(row.get("high") or 0)
        medium = int(row.get("medium") or 0)
        low = int(row.get("low") or 0)
        info = int(row.get("info") or 0)
        if high > 0:
            status = "FAIL"
        elif medium > 0:
            status = "WARN"
        else:
            status = "PASS"
        total_controls += high + medium + low + info
        table_rows.append(
            [
                area.title(),
                str(high),
                str(medium),
                str(low),
                str(info),
                status,
            ]
        )

    headers = ["Area", "High", "Medium", "Low", "Info", "Status"]
    print()
    print(f"Package   : {package}")
    print(f"Static ID : {static_run_id}")
    print(f"Session   : {run_row.get('session_label') or '—'}")
    print(f"Controls  : {total_controls}")
    table_utils.render_table(headers, sorted(table_rows, key=lambda item: item[0]))
    prompt_utils.press_enter_to_continue()


def prompt_masvs_overview() -> None:
    print()
    menu_utils.print_section("MASVS coverage overview")
    matrix = fetch_masvs_matrix()
    if not matrix:
        print(status_messages.status("No MASVS records available. Run a static analysis first.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    areas = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")
    summary_rows: list[list[str]] = []
    top_notes: list[str] = []

    for area in areas:
        fail = warn = passed = 0
        total_high = total_medium = 0
        top_package = None
        top_counts = (0, 0)
        for package, data in matrix.items():
            status = data["status"].get(area, "PASS")
            counts = data["counts"].get(area, {"high": 0, "medium": 0})
            high = counts.get("high", 0)
            medium = counts.get("medium", 0)
            total_high += high
            total_medium += medium
            if status == "FAIL":
                fail += 1
            elif status == "WARN":
                warn += 1
            else:
                passed += 1
            key_counts = (high, medium)
            if key_counts > top_counts:
                top_counts = key_counts
                top_package = package

        summary_rows.append(
            [
                area.title(),
                str(fail),
                str(warn),
                str(passed),
                str(total_high),
                str(total_medium),
            ]
        )
        if top_package and top_counts != (0, 0):
            top_notes.append(
                f"{area.title():<9} top package: {top_package} (high={top_counts[0]}, medium={top_counts[1]})"
            )

    headers = ["Area", "Fail", "Warn", "Pass", "High total", "Medium total"]
    table_utils.render_table(headers, summary_rows)
    if top_notes:
        print()
        print("Top offenders per area:")
        for line in top_notes:
            print(f"  {line}")
    prompt_utils.press_enter_to_continue()


def prompt_persistence_audit() -> None:
    print()
    menu_utils.print_section("Canonical runs missing baseline summaries")
    rows = _run_read_only(
        """
        SELECT sar.id AS static_run_id,
               a.package_name,
               sar.session_label,
               sar.created_at
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        LEFT JOIN static_findings_summary s
          ON s.static_run_id = sar.id
        WHERE s.id IS NULL
        ORDER BY sar.id DESC
        LIMIT 25
        """,
        fetch="all",
        dictionary=True,
    ) or []

    if not rows:
        print(
            status_messages.status(
                "All canonical static runs have matching baseline summary rows.",
                level="success",
            )
        )
        prompt_utils.press_enter_to_continue()
        return

    table_rows = []
    for row in rows:
        table_rows.append(
            [
                str(row.get("static_run_id") or "—"),
                row.get("package_name") or "—",
                row.get("session_label") or "—",
                str(coerce_datetime(row.get("created_at")) or row.get("created_at") or "—"),
            ]
        )
    headers = ["Static", "Package", "Session", "Created"]
    table_utils.render_table(headers, table_rows)
    prompt_utils.press_enter_to_continue()


def render_session_digest(session_stamp: str | None, *, header: str | None = None) -> None:
    resolved = session_stamp or _latest_session_stamp()
    if not resolved:
        print(status_messages.status("No sessions found in static runs.", level="warn"))
        return

    audit = collect_static_run_counts(session_stamp=resolved)
    if audit is None:
        print(status_messages.status("No static_analysis_runs row found for session.", level="warn"))
        return

    title = header or f"Verification digest — {resolved} (static_run_id={audit.static_run_id})"
    print()
    menu_utils.print_section(title)
    if audit.is_group_scope:
        print(status_messages.status("Group scope detected; per-package mapping not applicable.", level="info"))
    if audit.is_orphan:
        print(status_messages.status("Orphan static run (runs row missing).", level="warn"))

    optional_tables = {
        "static_string_selected_samples",
        "static_string_sample_sets",
    }
    canonical = [
        ("findings (normalized)", "findings"),
        ("static_findings (baseline)", "static_findings"),
        ("static_findings_summary", "static_findings_summary"),
        ("static_string_summary", "static_string_summary"),
        ("static_string_samples", "static_string_samples"),
        ("static_string_selected_samples (optional)", "static_string_selected_samples"),
        ("static_string_sample_sets (optional)", "static_string_sample_sets"),
        ("Risk buckets", "buckets"),
        ("Metrics", "metrics"),
        ("Permission audit snapshots", "permission_audit_snapshots"),
        ("Permission audit apps", "permission_audit_apps"),
    ]

    rows = []
    for label, key in canonical:
        count, status = audit.counts.get(key, (None, "SKIP"))
        if key in optional_tables and (status.startswith("SKIP") or count in (None, 0)):
            status = "SKIP (optional)"
        rows.append([label, str(count or 0), status])

    table_utils.render_table(["Table", "Rows", "Status"], rows)

    required = (
        "findings",
        "static_string_summary",
        "static_string_samples",
        "buckets",
        "metrics",
        "permission_audit_snapshots",
        "permission_audit_apps",
    )
    missing = [name for name in required if not audit.counts.get(name) or not audit.counts[name][0]]
    if audit.is_group_scope:
        if missing:
            status_line = f"DB verification: ERROR (missing {', '.join(sorted(missing))} for session={resolved})"
        else:
            status_line = "DB verification: OK (group scope; run_id not required)"
    elif audit.run_id is None:
        status_line = "DB verification: SKIPPED (run_id missing)"
    elif missing:
        status_line = f"DB verification: ERROR (missing {', '.join(sorted(missing))} for static_run_id={audit.static_run_id})"
    else:
        status_line = f"DB verification: OK (canonical tables populated for static_run_id={audit.static_run_id})"
    print(status_line)


def _latest_session_stamp() -> str | None:
    row = _run_read_only(
        "SELECT session_stamp FROM static_analysis_runs ORDER BY id DESC LIMIT 1",
        fetch="one",
        dictionary=True,
    )
    if not row:
        return None
    return row.get("session_stamp")


def _run_read_only(
    sql: str,
    params: tuple[Any, ...] | None = None,
    *,
    fetch: str = "all",
    dictionary: bool = False,
) -> Any:
    try:
        _ensure_read_only_sql(sql)
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return None
    return run_sql(sql, params, fetch=fetch, dictionary=dictionary)


def _ensure_read_only_sql(sql: str) -> None:
    if "--" in sql or "/*" in sql:
        raise RuntimeError("Read-only query rejected: SQL comments are not allowed.")
    cleaned = _strip_sql_comments(sql).strip()
    lowered = cleaned.lower().strip()
    stripped = lowered.rstrip(";").strip()
    if ";" in stripped:
        raise RuntimeError("Read-only query rejected: multi-statement SQL is not allowed.")
    if not stripped.startswith(("select", "with", "explain")):
        raise RuntimeError("Read-only query rejected: only SELECT/WITH/EXPLAIN statements are allowed.")
    forbidden = re.search(
        r"\b(insert|update|delete|drop|alter|create|truncate|rename|grant|revoke|call|set|use)\b",
        stripped,
    )
    if forbidden:
        raise RuntimeError(f"Read-only query rejected: forbidden keyword '{forbidden.group(1)}' detected.")


def _strip_sql_comments(sql: str) -> str:
    sql = re.sub(r"(?s)/\*.*?\*/", " ", sql)
    sql = re.sub(r"(?m)--.*?$", " ", sql)
    return sql


__all__ = [
    "run_query_menu",
    "show_latest_session",
    "prompt_session_counts",
    "prompt_runs_for_package",
    "prompt_harvest_for_package",
    "prompt_masvs_by_package",
    "prompt_masvs_overview",
    "prompt_persistence_audit",
    "render_session_digest",
]
