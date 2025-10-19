"""Curated database queries to verify static-analysis persistence."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from .sql_helpers import coerce_datetime


def run_query_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Run Database Queries")

        options: Sequence[Tuple[str, str, str]] = (
            ("1", "Latest session snapshot", "Show most recent session stamp and table counts."),
            ("2", "Session table counts", "Enter a session stamp to validate static tables."),
            ("3", "Runs and buckets by package", "List runs for a package with bucket totals."),
            ("4", "Harvest artefacts by package", "Show harvested APK records for a package."),
            ("0", "Back", "Return to Database Utilities."),
        )
        menu_utils.print_menu(options, padding=True, show_exit=False)
        choice = prompt_utils.get_choice([opt[0] for opt in options])

        if choice == "1":
            _show_latest_session()
        elif choice == "2":
            _show_session_counts()
        elif choice == "3":
            _show_runs_for_package()
        elif choice == "4":
            _show_harvest_for_package()
        elif choice == "0":
            break


def _show_latest_session() -> None:
    print()
    menu_utils.print_section("Latest session snapshot")
    session = run_sql(
        """
        SELECT session_stamp, package_name, created_at
        FROM static_findings_summary
        ORDER BY created_at DESC
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
    print(f"Session stamp : {session_stamp}")
    print(f"Package       : {package or '—'}")
    print(f"Created at    : {created_at or session.get('created_at')}")
    print()

    _print_session_counts(session_stamp)
    prompt_utils.press_enter_to_continue()


def _show_session_counts() -> None:
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


def _show_runs_for_package() -> None:
    package = prompt_utils.prompt_text("Package name", required=False).strip()
    if not package:
        print(status_messages.status("Package name is required.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    rows = run_sql(
        """
        SELECT r.run_id,
               r.session_stamp,
               r.version_name,
               r.target_sdk,
               r.ts,
               COUNT(b.bucket) AS bucket_count,
               SUM(b.points) AS bucket_points
        FROM runs r
        LEFT JOIN buckets b ON b.run_id = r.run_id
        WHERE r.package = %s
        GROUP BY r.run_id, r.session_stamp, r.version_name, r.target_sdk, r.ts
        ORDER BY r.run_id DESC
        LIMIT 20
        """,
        (package,),
        fetch="all",
        dictionary=True,
    )

    print()
    menu_utils.print_section(f"Runs for {package}")
    if not rows:
        print(status_messages.status("No runs found for package.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    table_rows: List[List[str]] = []
    for row in rows:
        table_rows.append(
            [
                str(row["run_id"]),
                row.get("session_stamp") or "—",
                row.get("version_name") or "—",
                str(row.get("target_sdk") or "—"),
                str(coerce_datetime(row.get("ts")) or row.get("ts") or "—"),
                str(row.get("bucket_count") or 0),
                str(row.get("bucket_points") or 0),
            ]
        )
    headers = ["Run", "Session", "Version", "targetSdk", "Timestamp", "Buckets", "Points"]
    table_utils.render_table(headers, table_rows)
    prompt_utils.press_enter_to_continue()


def _show_harvest_for_package() -> None:
    package = prompt_utils.prompt_text("Package name", required=False).strip()
    if not package:
        print(status_messages.status("Package name is required.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    rows = run_sql(
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
        print(status_messages.status("No harvested artefacts found for package.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    table_rows: List[List[str]] = []
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


def _print_session_counts(session_stamp: str) -> None:
    def _scalar(sql: str, params: Tuple[Any, ...]) -> int:
        try:
            value = run_sql(sql, params, fetch="one")
        except Exception:
            return 0
        if isinstance(value, dict):
            value = next(iter(value.values()), 0)
        if not value:
            return 0
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    counts = [
        ("static_findings_summary", _scalar("SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp=%s", (session_stamp,))),
        ("static_findings", _scalar("SELECT COUNT(*) FROM static_findings f JOIN static_findings_summary s ON s.id=f.summary_id WHERE s.session_stamp=%s", (session_stamp,))),
        ("static_string_summary", _scalar("SELECT COUNT(*) FROM static_string_summary WHERE session_stamp=%s", (session_stamp,))),
        ("static_string_samples", _scalar("SELECT COUNT(*) FROM static_string_samples x JOIN static_findings_summary s ON s.id=x.summary_id WHERE s.session_stamp=%s", (session_stamp,))),
        ("static_provider_acl", _scalar("SELECT COUNT(*) FROM static_provider_acl WHERE session_stamp=%s", (session_stamp,))),
        ("static_fileproviders", _scalar("SELECT COUNT(*) FROM static_fileproviders WHERE session_stamp=%s", (session_stamp,))),
        ("runs", _scalar("SELECT COUNT(*) FROM runs WHERE session_stamp=%s", (session_stamp,))),
        ("buckets", _scalar("SELECT COUNT(*) FROM buckets b JOIN runs r ON r.run_id=b.run_id WHERE r.session_stamp=%s", (session_stamp,))),
        ("metrics", _scalar("SELECT COUNT(*) FROM metrics m JOIN runs r ON r.run_id=m.run_id WHERE r.session_stamp=%s", (session_stamp,))),
    ]

    headers = ["Table", "Rows"]
    rows = [[name, str(value)] for name, value in counts]
    table_utils.render_table(headers, rows)


def _latest_session_stamp() -> Optional[str]:
    row = run_sql(
        "SELECT session_stamp FROM static_findings_summary ORDER BY created_at DESC LIMIT 1",
        fetch="one",
        dictionary=True,
    )
    if not row:
        return None
    return row.get("session_stamp")


__all__ = ["run_query_menu"]
