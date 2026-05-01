"""Diagnostics and verification helpers for the static analysis CLI."""

from __future__ import annotations

from collections.abc import Callable

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.menus import query_runner
from scytaledroid.Database.db_utils.menus.sql_helpers import coerce_datetime
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils import table_utils


def _fetch_recent_static_runs(*, limit: int = 15, search: str | None = None) -> list[dict[str, object]]:
    clauses: list[str] = []
    params: list[object] = []
    if search:
        token = f"%{search.strip()}%"
        clauses.append("(a.package_name LIKE %s OR COALESCE(a.display_name, '') LIKE %s)")
        params.extend([token, token])

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(int(limit))
    rows = core_q.run_sql(
        f"""
        SELECT
          sar.id AS static_run_id,
          sar.session_stamp,
          sar.profile,
          sar.status,
          (
            SELECT COUNT(*)
            FROM static_analysis_findings sf
            WHERE sf.run_id = sar.id
          ) AS findings_total,
          sar.created_at,
          a.package_name,
          COALESCE(a.display_name, a.package_name) AS app_label,
          av.version_code,
          av.version_name
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        {where_sql}
        ORDER BY sar.id DESC
        LIMIT %s
        """,
        tuple(params),
        fetch="all_dict",
        dictionary=True,
    ) or []
    return [dict(row) for row in rows]


def _render_static_run_detail(row: dict[str, object]) -> None:
    static_run_id = int(row["static_run_id"])
    findings = core_q.run_sql(
        "SELECT COUNT(*) AS c FROM static_analysis_findings WHERE run_id = %s",
        (static_run_id,),
        fetch="one_dict",
        dictionary=True,
    ) or {"c": 0}
    permissions = core_q.run_sql(
        "SELECT COUNT(*) AS c FROM static_permission_matrix WHERE run_id = %s",
        (static_run_id,),
        fetch="one_dict",
        dictionary=True,
    ) or {"c": 0}
    risk_rows = core_q.run_sql(
        "SELECT COUNT(*) AS c FROM static_permission_risk_vnext WHERE run_id = %s",
        (static_run_id,),
        fetch="one_dict",
        dictionary=True,
    ) or {"c": 0}

    print()
    menu_utils.print_header("Static Run Detail", str(row.get("app_label") or row.get("package_name") or ""))
    menu_utils.print_metrics(
        [
            ("Static run", static_run_id),
            ("Session", row.get("session_stamp") or "—"),
            ("Package", row.get("package_name") or "—"),
            ("Version", f"{row.get('version_name') or '—'} ({row.get('version_code') or '—'})"),
            ("Profile", row.get("profile") or "—"),
            ("Status", row.get("status") or "—"),
            ("Created", coerce_datetime(row.get("created_at")) or row.get("created_at") or "—"),
            ("Findings", findings.get("c", 0)),
            ("Perm rows", permissions.get("c", 0)),
            ("Risk rows", risk_rows.get("c", 0)),
        ]
    )
    prompt_utils.press_enter_to_continue()


def _browse_recent_static_runs(*, search: str | None = None) -> None:
    rows = _fetch_recent_static_runs(limit=15, search=search)
    print()
    menu_utils.print_section("Recent Static Runs" if not search else f"Recent Static Runs — {search}")
    if not rows:
        print(status_messages.status("No static runs found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    table_rows: list[list[str]] = []
    valid_choices: list[str] = ["0"]
    for idx, row in enumerate(rows, start=1):
        valid_choices.append(str(idx))
        table_rows.append(
            [
                str(idx),
                str(row.get("app_label") or "—"),
                str(row.get("version_code") or "—"),
                str(row.get("profile") or "—"),
                str(row.get("status") or "—"),
                str(coerce_datetime(row.get("created_at")) or row.get("created_at") or "—"),
            ]
        )
    table_utils.render_table(
        ["#", "App", "Code", "Profile", "Status", "Created"],
        table_rows,
    )
    print("0) Back")
    choice = prompt_utils.get_choice(valid_choices, default="0")
    if choice == "0":
        return
    _render_static_run_detail(rows[int(choice) - 1])


def _search_static_runs() -> None:
    query = prompt_utils.prompt_text("Package or app name", required=False).strip()
    if not query:
        return
    _browse_recent_static_runs(search=query)


def _scalar(sql: str, params: tuple[object, ...] = ()) -> int:
    row = core_q.run_sql(sql, params, fetch="one") or ()
    return int((row[0] if row else 0) or 0)


def _latest_static_session_stamp() -> str | None:
    row = core_q.run_sql(
        "SELECT session_stamp FROM static_analysis_runs ORDER BY id DESC LIMIT 1",
        fetch="one",
    ) or ()
    stamp = str(row[0]).strip() if row and row[0] is not None else ""
    return stamp or None


def _show_latest_static_coverage() -> None:
    print()
    menu_utils.print_section("Latest static coverage")
    session_stamp = _latest_static_session_stamp()
    if not session_stamp:
        print(status_messages.status("No static session found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    static_run_ids_sql = "SELECT id FROM static_analysis_runs WHERE session_stamp=%s"
    menu_utils.print_metrics([("Session", session_stamp)])
    print()

    checks: list[tuple[str, Callable[[], tuple[int, int | None, str]]]] = [
        (
            "Canonical runs",
            lambda: (
                _scalar("SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s", (session_stamp,)),
                _scalar(
                    "SELECT SUM(CASE WHEN UPPER(COALESCE(status,''))='COMPLETED' THEN 1 ELSE 0 END) "
                    "FROM static_analysis_runs WHERE session_stamp=%s",
                    (session_stamp,),
                ),
                "rows",
            ),
        ),
        (
            "Findings",
            lambda: (
                _scalar(
                    f"SELECT COUNT(*) FROM static_analysis_findings WHERE run_id IN ({static_run_ids_sql})",
                    (session_stamp,),
                ),
                None,
                "rows",
            ),
        ),
        (
            "Permission matrix",
            lambda: (
                _scalar(
                    f"SELECT COUNT(*) FROM static_permission_matrix WHERE run_id IN ({static_run_ids_sql})",
                    (session_stamp,),
                ),
                None,
                "rows",
            ),
        ),
        (
            "Permission risk",
            lambda: (
                _scalar(
                    f"SELECT COUNT(*) FROM static_permission_risk_vnext WHERE run_id IN ({static_run_ids_sql})",
                    (session_stamp,),
                ),
                None,
                "rows",
            ),
        ),
        (
            "Correlation results",
            lambda: (
                _scalar(
                    f"SELECT COUNT(*) FROM static_correlation_results WHERE static_run_id IN ({static_run_ids_sql})",
                    (session_stamp,),
                ),
                _scalar(
                    f"SELECT COUNT(DISTINCT package_name) FROM static_correlation_results "
                    f"WHERE static_run_id IN ({static_run_ids_sql})",
                    (session_stamp,),
                ),
                "pkgs",
            ),
        ),
        (
            "Provider ACL",
            lambda: (
                _scalar("SELECT COUNT(*) FROM static_provider_acl WHERE session_stamp=%s", (session_stamp,)),
                _scalar(
                    "SELECT COUNT(DISTINCT package_name) FROM static_provider_acl WHERE session_stamp=%s",
                    (session_stamp,),
                ),
                "pkgs",
            ),
        ),
        (
            "File providers",
            lambda: (
                _scalar(
                    f"SELECT COUNT(*) FROM static_fileproviders WHERE run_id IN ({static_run_ids_sql})",
                    (session_stamp,),
                ),
                _scalar(
                    f"SELECT COUNT(DISTINCT package_name) FROM static_fileproviders "
                    f"WHERE run_id IN ({static_run_ids_sql})",
                    (session_stamp,),
                ),
                "pkgs",
            ),
        ),
        (
            "Permission audit snapshots",
            lambda: (
                _scalar(
                    f"SELECT COUNT(*) FROM permission_audit_snapshots WHERE static_run_id IN ({static_run_ids_sql})",
                    (session_stamp,),
                ),
                _scalar(
                    f"SELECT COUNT(*) FROM permission_audit_apps WHERE static_run_id IN ({static_run_ids_sql})",
                    (session_stamp,),
                ),
                "apps",
            ),
        ),
        (
            "Session links",
            lambda: (
                _scalar("SELECT COUNT(*) FROM static_session_run_links WHERE session_stamp=%s", (session_stamp,)),
                None,
                "rows",
            ),
        ),
        (
            "Summary cache",
            lambda: (
                _scalar(
                    "SELECT COUNT(*) FROM web_static_dynamic_app_summary_cache WHERE latest_static_session_stamp=%s",
                    (session_stamp,),
                ),
                None,
                "rows",
            ),
        ),
    ]

    table_rows: list[list[str]] = []
    for label, loader in checks:
        try:
            primary, secondary, secondary_label = loader()
        except Exception as exc:
            table_rows.append([label, "—", "query_failed", exc.__class__.__name__])
            continue
        note = "OK" if primary > 0 else "missing"
        if secondary is not None:
            note = f"{secondary_label}={secondary}"
            if primary == 0 and secondary == 0:
                note = f"missing ({note})"
        table_rows.append([label, str(primary), note, ""])

    table_utils.render_table(["Surface", "Rows", "Coverage", "Note"], table_rows)
    print()
    print("Reading guide")
    print("-------------")
    print("Rows=0 is usually a wiring, persistence, or applicability gap.")
    print("Low package coverage on a broad detector often means detector sparsity or session-link mismatch.")
    prompt_utils.press_enter_to_continue()


def render_static_diagnostics_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Static Run History")
        menu_utils.print_hint(
            "Browse canonical static runs first; use diagnostics for lower-level table checks when needed."
        )
        menu_utils.print_section("Actions")
        options = {
            "1": "Browse recent static runs",
            "2": "Search static runs by package/app",
            "3": "Latest session snapshot",
            "4": "Session table counts",
            "5": "Canonical + legacy run lineage by package",
            "6": "Harvest artifacts by package",
            "7": "Latest static coverage",
            "8": "Active static session",
            "9": "Summary cache status",
        }
        menu_utils.print_menu(options, padding=True, show_exit=True)
        choice = prompt_utils.get_choice(list(options.keys()) + ["0"])

        if choice == "0":
            break
        if choice == "1":
            _browse_recent_static_runs()
        elif choice == "2":
            _search_static_runs()
        elif choice == "3":
            query_runner.show_latest_session()
        elif choice == "4":
            query_runner.prompt_session_counts()
        elif choice == "5":
            query_runner.prompt_runs_for_package()
        elif choice == "6":
            query_runner.prompt_harvest_for_package()
        elif choice == "7":
            _show_latest_static_coverage()
        elif choice == "8":
            query_runner.show_active_static_session_status()
        elif choice == "9":
            query_runner.show_summary_cache_status()


__all__ = ["render_static_diagnostics_menu"]
