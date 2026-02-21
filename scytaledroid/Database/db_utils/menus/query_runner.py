"""Curated database queries to verify static-analysis persistence."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Database.db_scripts.static_run_audit import collect_static_run_counts
from scytaledroid.StaticAnalysis.cli.reports.masvs_summary_report import fetch_masvs_matrix
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from .sql_helpers import coerce_datetime


def run_query_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Curated Read-only Queries")

        options: Sequence[tuple[str, str, str]] = (
            ("1", "Latest session snapshot", "Show most recent session stamp and table counts."),
            ("2", "Session table counts", "Enter a session stamp to validate static tables."),
            ("3", "Runs and buckets by package", "List run metadata and scoring buckets."),
            ("4", "Harvest artifacts by package", "Show harvested APK records for a package."),
        )
        spec = menu_utils.MenuSpec(
            items=options,
            show_exit=True,
            exit_label="Back",
            padding=True,
        )
        menu_utils.render_menu(spec)
        choice = prompt_utils.get_choice(menu_utils.selectable_keys(options, include_exit=True))

        if choice == "1":
            show_latest_session()
        elif choice == "2":
            prompt_session_counts()
        elif choice == "3":
            prompt_runs_for_package()
        elif choice == "4":
            prompt_harvest_for_package()
        elif choice == "0":
            break


def show_latest_session() -> None:
    print()
    menu_utils.print_section("Latest session snapshot")
    session = _run_read_only(
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

    table_rows: list[list[str]] = []
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


def _print_session_counts(session_stamp: str) -> None:
    audit = collect_static_run_counts(session_stamp=session_stamp)
    if not audit:
        print(status_messages.status("No matching session found.", level="warn"))
        return

    print(f"Static run id : {audit.static_run_id}")
    print(f"Run id        : {audit.run_id or '—'}")
    print(f"Scope label   : {audit.scope_label or '—'}")
    print()

    table_rows: list[list[str]] = []
    for table, (count, status) in audit.counts.items():
        table_rows.append([table, str(count) if count is not None else "—", status])

    table_utils.render_table(["Table", "Rows", "Status"], table_rows)


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
            SELECT run_id, session_stamp
            FROM runs
            WHERE package = %s
            ORDER BY run_id DESC
            LIMIT 1
            """,
            (package,),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        run_row = None
    if not run_row:
        print(status_messages.status(f"No runs recorded for package '{package}'.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    run_id = int(run_row.get("run_id") or 0)

    try:
        rows = _run_read_only(
            """
            SELECT masvs,
                   SUM(CASE WHEN severity='High' THEN 1 ELSE 0 END) AS high,
                   SUM(CASE WHEN severity='Medium' THEN 1 ELSE 0 END) AS medium,
                   SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END) AS low,
                   SUM(CASE WHEN severity='Info' THEN 1 ELSE 0 END) AS info
            FROM findings
            WHERE run_id = %s
            GROUP BY masvs
            """,
            (run_id,),
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        rows = []

    if not rows:
        print(status_messages.status(f"No MASVS-tagged findings for package '{package}' (run_id={run_id}).", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    table_rows: list[list[str]] = []
    total_controls = 0
    for row in rows:
        area = (row.get("masvs") or "").upper() or "UNKNOWN"
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
    print(f"Run ID    : {run_id}")
    print(f"Session   : {run_row.get('session_stamp') or '—'}")
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
    menu_utils.print_section("Runs missing findings summaries")
    rows = _run_read_only(
        """
        SELECT r.run_id,
               r.package,
               r.session_stamp,
               r.ts
        FROM runs r
        LEFT JOIN static_findings_summary s
          ON s.package_name = r.package
         AND s.session_stamp = r.session_stamp
        WHERE s.id IS NULL
        ORDER BY r.run_id DESC
        LIMIT 25
        """,
        fetch="all",
        dictionary=True,
    ) or []

    if not rows:
        print(status_messages.status("All recorded runs have matching static findings summaries.", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    table_rows = []
    for row in rows:
        table_rows.append(
            [
                str(row.get("run_id") or "—"),
                row.get("package") or "—",
                row.get("session_stamp") or "—",
                str(coerce_datetime(row.get("ts")) or row.get("ts") or "—"),
            ]
        )
    headers = ["Run ID", "Package", "Session", "Created"]
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
