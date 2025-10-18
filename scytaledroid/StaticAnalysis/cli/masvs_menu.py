"""Read-only MASVS summary and risk-scoring explainer entries for the CLI."""

from __future__ import annotations

from typing import Optional

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Database.db_core import db_queries as core_q

from .masvs_summary import fetch_db_masvs_summary


def render_masvs_summary_menu() -> None:
    run_id = _select_run_id()
    if run_id is None:
        print(status_messages.status("No runs available. Execute a full analysis first.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    result = fetch_db_masvs_summary(run_id)
    if result is None:
        print(status_messages.status("No database-backed MASVS data available (run full analysis first).", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    run_id, rows = result
    print()
    menu_utils.print_header("MASVS Summary", f"run_id={run_id}")
    headers = ["Area", "High", "Med", "Low", "Info", "Status", "Worst CVSS"]
    table: list[list[str]] = []
    passes = 0
    for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE"):
        entry = next((row for row in rows if row["area"] == area), None)
        if entry is None:
            table.append([area.title(), "0", "0", "0", "0", "PASS", "—"])
            passes += 1
            continue
        sev_ge_med = entry["sev_ge_med"]
        low = entry["low"]
        info = entry["info"]
        status = "PASS" if sev_ge_med == 0 else "FAIL"
        if status == "PASS":
            passes += 1
        table.append([
            area.title(),
            "0",
            str(sev_ge_med),
            str(low),
            str(info),
            status,
            entry["worst"],
        ])
    table_utils.render_table(headers, table)
    pct = int(round((passes / 4) * 100))
    print(f"Pass percentage: {pct}%")
    prompt_utils.press_enter_to_continue()


def _select_run_id() -> Optional[int]:
    try:
        rows = core_q.run_sql("SELECT run_id FROM runs ORDER BY run_id DESC LIMIT 10", fetch="all") or []
    except Exception:
        return None
    if not rows:
        return None
    options = [str(row[0]) for row in rows]
    default = options[0]
    menu_utils.print_section("Available runs")
    for value in options:
        print(f"  - {value}")
    choice = prompt_utils.prompt_text("Enter run_id (default latest)", default=default, required=False)
    chosen = choice.strip() or default
    if chosen not in options:
        try:
            return int(chosen)
        except ValueError:
            return int(default)
    return int(chosen)


def render_scoring_explainer_menu() -> None:
    print()
    menu_utils.print_header("Risk Scoring", "Explainer")
    try:
        from scytaledroid.StaticAnalysis.modules.permissions.simple import render_scoring_legend
        render_scoring_legend()
    except Exception as exc:
        print(status_messages.status(f"Unable to render scoring legend: {exc}", level="warn"))
    prompt_utils.press_enter_to_continue()


__all__ = ["render_masvs_summary_menu", "render_scoring_explainer_menu"]
