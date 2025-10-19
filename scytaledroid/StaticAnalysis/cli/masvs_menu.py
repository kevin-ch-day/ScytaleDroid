"""Read-only MASVS summary and risk-scoring explainer entries for the CLI."""

from __future__ import annotations

from statistics import median
from typing import Optional, Dict

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils, colors
from scytaledroid.Database.db_core import db_queries as core_q

from .masvs_summary import fetch_db_masvs_summary, fetch_masvs_matrix


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
    headers = ["Area", "High", "Med", "Low", "Info", "Status", "Worst CVSS", "Controls"]
    table: list[list[str]] = []
    passes = 0
    for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE"):
        entry = next((row for row in rows if row["area"] == area), None)
        if entry is None:
            table.append([area.title(), "0", "0", "0", "0", "PASS", "—", "0/0"])
            passes += 1
            continue
        high = entry.get("high", 0)
        medium = entry.get("medium", 0)
        sev_ge_med = int(high) + int(medium)
        low = entry["low"]
        info = entry["info"]
        if high > 0:
            status = "FAIL"
        elif medium > 0:
            status = "WARN"
        else:
            status = "PASS"
        if status == "PASS":
            passes += 1
        total_controls = int(entry.get("control_count") or high + medium + low + info)
        affected = high + medium
        table.append([
            area.title(),
            str(high),
            str(medium),
            str(low),
            str(info),
            status,
            entry["worst"],
            f"{affected}/{total_controls}" if total_controls else "0/0",
        ])
    table_utils.render_table(headers, table)
    pct = int(round((passes / 4) * 100))
    print(f"Pass percentage (no high findings): {pct}%")
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


def render_masvs_matrix_menu() -> None:
    matrix = fetch_masvs_matrix()
    if not matrix:
        print(status_messages.status("No MASVS findings recorded yet. Run a full analysis first.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("MASVS Matrix", "Latest runs per package")

    headers = ["Package", "Network", "Platform", "Privacy", "Storage", "Pass %", "Score"]
    areas = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")
    rows: list[list[str]] = []
    total_packages = len(matrix)
    fail_packages = 0
    warn_packages = 0
    aggregate_pass = 0
    pass_rates: list[int] = []
    area_pass_totals: Dict[str, int] = {area: 0 for area in areas}
    score_values: list[float] = []

    def _clip(text: str, limit: int = 36) -> str:
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    for package, data in matrix.items():
        statuses: Dict[str, str] = data["status"]
        counts: Dict[str, Dict[str, int]] = data["counts"]
        pass_rate = data["pass_rate"]
        top_lookup = data.get("top") or {}

        def _fmt(area: str) -> str:
            status = statuses.get(area, "–")
            area_counts = counts.get(area, {"high": 0, "medium": 0, "low": 0, "info": 0})
            top_entry = top_lookup.get(area, {})
            suffix = ""
            if status == "FAIL":
                high = area_counts.get("high", 0)
                top_high = top_entry.get("high") if isinstance(top_entry, dict) else None
                if top_high:
                    descriptor = _clip(str(top_high.get("descriptor", "")) or "High finding")
                    occurrences = int(top_high.get("occurrences") or 0)
                    suffix = f" – {descriptor}"
                    if occurrences > 1:
                        suffix += f"x{occurrences}"
                text = f"FAIL (H{high}){suffix}"
                return colors.apply(text, colors.style("error"), bold=True)
            if status == "WARN":
                medium = area_counts.get("medium", 0)
                top_medium = top_entry.get("medium") if isinstance(top_entry, dict) else None
                if top_medium:
                    descriptor = _clip(str(top_medium.get("descriptor", "")) or "Medium finding")
                    occurrences = int(top_medium.get("occurrences") or 0)
                    suffix = f" – {descriptor}"
                    if occurrences > 1:
                        suffix += f"x{occurrences}"
                text = f"WARN (M{medium}){suffix}"
                return colors.apply(text, colors.style("warning"), bold=True)
            if status == "PASS":
                total_controls = (
                    area_counts.get("high", 0)
                    + area_counts.get("medium", 0)
                    + area_counts.get("low", 0)
                    + area_counts.get("info", 0)
                )
                if total_controls:
                    suffix = f" ({total_controls} ctrl{'s' if total_controls != 1 else ''})"
                else:
                    suffix = ""
                text = f"PASS{suffix}"
                return colors.apply(text, colors.style("success"), bold=True)
            return status

        if any(status == "FAIL" for status in statuses.values()):
            fail_packages += 1
        elif any(status == "WARN" for status in statuses.values()):
            warn_packages += 1
        aggregate_pass += pass_rate
        pass_rates.append(pass_rate)
        for area in area_pass_totals:
            if statuses.get(area, "PASS") == "PASS":
                area_pass_totals[area] += 1
        score = 0.0
        for area in areas:
            status = statuses.get(area, "PASS")
            if status == "PASS":
                score += 1.0
            elif status == "WARN":
                score += 0.5
        score_values.append(score)
        rows.append(
            [
                package,
                _fmt("NETWORK"),
                _fmt("PLATFORM"),
                _fmt("PRIVACY"),
                _fmt("STORAGE"),
                f"{pass_rate:>3}%",
                f"{score:.1f}/4",
            ]
        )

    table_utils.render_table(headers, rows)

    avg_pass = aggregate_pass / total_packages if total_packages else 0
    score_avg = sum(score_values) / total_packages if total_packages else 0
    min_pass = min(pass_rates) if pass_rates else 0
    max_pass = max(pass_rates) if pass_rates else 0
    median_pass = float(median(pass_rates)) if pass_rates else 0
    print()
    print(status_messages.status(f"Packages analysed: {total_packages}", level="info"))
    print(status_messages.status(f"Packages with FAIL (High severity): {fail_packages}", level="error"))
    print(status_messages.status(f"Packages with WARN only (Medium severity): {warn_packages}", level="warning"))
    print(status_messages.status(f"Average MASVS pass rate: {avg_pass:.1f}% (median {median_pass:.1f}%, min {min_pass}%, max {max_pass}%)", level="info"))
    print(status_messages.status(f"Average MASVS score: {score_avg:.2f}/4.00", level="info"))
    if total_packages:
        print()
        for area, count in area_pass_totals.items():
            pct = (count / total_packages) * 100
            label = area.title()
            print(status_messages.status(f"{label:9} pass coverage: {count}/{total_packages} ({pct:.0f}%)", level="info"))
    print()
    print("Legend:")
    print(f"  {colors.apply('PASS', colors.style('success'), bold=True)}  No medium/high findings - contributes 1.0 to score")
    print(f"  {colors.apply('WARN', colors.style('warning'), bold=True)}  Medium findings present - contributes 0.5 to score")
    print(f"  {colors.apply('FAIL', colors.style('error'), bold=True)}  High findings present - contributes 0.0 to score")

    actionable_packages = sorted(
        {
            package
            for package, data in matrix.items()
            if any(data["status"].get(area) in {"FAIL", "WARN"} for area in areas)
        }
    )
    if actionable_packages:
        print()
        menu_utils.print_hint(
            "Drill down to see the leading findings per area (leave blank to skip).", icon="?"
        )

        def _render_package_detail(target: str) -> None:
            data = matrix.get(target)
            if not data:
                print(status_messages.status(f"Package '{target}' not found in latest runs.", level="warn"))
                return
            menu_utils.print_section(f"Matrices - {target}")
            status_map = data["status"]
            count_map = data["counts"]
            top_map = data.get("top") or {}

            def _status_token(label: str) -> str:
                if label == "FAIL":
                    return colors.apply(label, colors.style("error"), bold=True)
                if label == "WARN":
                    return colors.apply(label, colors.style("warning"), bold=True)
                if label == "PASS":
                    return colors.apply(label, colors.style("success"), bold=True)
                return label

            detail_rows: list[list[str]] = []
            for area in areas:
                counts = count_map.get(area, {"high": 0, "medium": 0, "low": 0, "info": 0})
                status = status_map.get(area, "PASS")
                top_entry = top_map.get(area, {})
                descriptor = ""
                if status == "FAIL":
                    top_high = top_entry.get("high") if isinstance(top_entry, dict) else None
                    if top_high:
                        desc = _clip(str(top_high.get("descriptor") or "High finding"), limit=48)
                        occ = int(top_high.get("occurrences") or 0)
                        descriptor = f"High - {desc}"
                        if occ > 1:
                            descriptor += f" (x{occ})"
                    else:
                        descriptor = "High finding present"
                elif status == "WARN":
                    top_medium = top_entry.get("medium") if isinstance(top_entry, dict) else None
                    if top_medium:
                        desc = _clip(str(top_medium.get("descriptor") or "Medium finding"), limit=48)
                        occ = int(top_medium.get("occurrences") or 0)
                        descriptor = f"Medium - {desc}"
                        if occ > 1:
                            descriptor += f" (x{occ})"
                    else:
                        descriptor = "Medium finding present"
                else:
                    total_ctrls = counts.get("high", 0) + counts.get("medium", 0) + counts.get("low", 0) + counts.get("info", 0)
                    descriptor = f"{total_ctrls} control{'s' if total_ctrls != 1 else ''} assessed"
                detail_rows.append(
                    [
                        area.title(),
                        _status_token(status),
                        str(counts.get("high", 0)),
                        str(counts.get("medium", 0)),
                        str(counts.get("low", 0)),
                        str(counts.get("info", 0)),
                        descriptor,
                    ]
                )
            table_utils.render_table(
                ["Area", "Status", "High", "Med", "Low", "Info", "Context"],
                detail_rows,
            )
            package_score = sum(
                1.0 if status_map.get(area, "PASS") == "PASS" else 0.5 if status_map.get(area) == "WARN" else 0.0
                for area in areas
            )
            package_pass_rate = data.get("pass_rate", 0)
            print(
                status_messages.status(
                    f"Score: {package_score:.1f}/4 - Pass rate: {package_pass_rate:.0f}%",
                    level="info",
                )
            )
            print()

        seen_any = False
        while True:
            hint = ", ".join(actionable_packages[:6])
            choice = prompt_utils.prompt_text(
                "Package to inspect",
                required=False,
                hint=f"Available: {hint}" if actionable_packages else None,
            ).strip()
            if not choice:
                break
            if choice not in matrix:
                print(status_messages.status("Package not recognised. Try again.", level="warn"))
                continue
            _render_package_detail(choice)
            seen_any = True
            if not prompt_utils.prompt_yes_no("Inspect another package?", default=False):
                break
        if seen_any:
            print()

    prompt_utils.press_enter_to_continue()


__all__ = ["render_masvs_summary_menu", "render_scoring_explainer_menu", "render_masvs_matrix_menu"]
