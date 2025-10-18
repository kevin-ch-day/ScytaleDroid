"""Read-only MASVS summary and risk-scoring explainer entries for the CLI."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def render_masvs_summary_menu() -> None:
    """Load the most recent baseline JSON and print a MASVS summary per app."""
    base_dir = Path(app_config.DATA_DIR) / "static_analysis" / "baseline"
    if not base_dir.exists():
        print(status_messages.status("No baseline reports found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    files = sorted(base_dir.glob("*.json"))
    if not files:
        print(status_messages.status("No baseline reports found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    latest = files[-1]
    try:
        payload = json.loads(latest.read_text("utf-8"))
    except Exception as exc:
        print(status_messages.status(f"Failed to read baseline JSON: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    findings = payload.get("baseline", {}).get("findings", [])
    if not isinstance(findings, list):
        findings = []
    areas = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")
    counts = {area: {"High": 0, "Medium": 0, "Low": 0, "Info": 0} for area in areas}
    for f in findings:
        if not isinstance(f, dict):
            continue
        area = str(f.get("category_masvs") or "").upper()
        severity = str(f.get("severity") or "Info")
        if area in counts and severity in counts[area]:
            counts[area][severity] = counts[area].get(severity, 0) + 1

    print()
    menu_utils.print_header("MASVS Summary", str(latest.name))
    headers = ["Area", "High", "Med", "Low", "Info", "Status"]
    rows: list[list[str]] = []
    passes = 0
    for area in areas:
        c = counts[area]
        status = "PASS" if (c["High"] + c["Medium"]) == 0 else "FAIL"
        if status == "PASS":
            passes += 1
        rows.append([area.title(), str(c["High"]), str(c["Medium"]), str(c["Low"]), str(c["Info"]), status])
    from scytaledroid.Utils.DisplayUtils import table_utils as _tu
    _tu.render_table(headers, rows)
    pct = int(round((passes / len(areas)) * 100)) if areas else 0
    print(f"Pass percentage: {pct}%")
    prompt_utils.press_enter_to_continue()


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

