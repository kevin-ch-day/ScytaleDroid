"""Read-only MASVS summary and risk-scoring explainer entries for the CLI."""

from __future__ import annotations

import re
from statistics import median
from typing import Optional, Dict, Mapping

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils, colors
from scytaledroid.Database.db_core import db_queries as core_q

from ..reports.masvs_summary_report import fetch_db_masvs_summary, fetch_masvs_matrix


def _humanize_descriptor(raw: object | None) -> str:
    if raw is None:
        return ""
    try:
        text = str(raw)
    except Exception:
        return ""
    cleaned = re.sub(r"[_\-]+", " ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return ""
    if cleaned.isupper():
        return cleaned
    return cleaned.title()


def _format_descriptor(entry: Mapping[str, object] | None, severity: str) -> str:
    if not isinstance(entry, Mapping):
        return ""
    descriptor = _humanize_descriptor(entry.get("descriptor"))
    if not descriptor:
        descriptor = f"{severity.title()} finding"
    try:
        occurrences = int(entry.get("occurrences") or 0)
    except Exception:
        occurrences = 0
    if occurrences > 1:
        descriptor += f" ×{occurrences}"
    return descriptor


def _format_cvss(entry: Dict[str, object]) -> tuple[str, str, str]:
    cvss = entry.get("cvss") if isinstance(entry, dict) else None
    if not isinstance(cvss, dict):
        return "—", "—", "—"
    worst_score = cvss.get("worst_score")
    worst_band = cvss.get("worst_severity") or ""
    worst_identifier = cvss.get("worst_identifier") or ""
    if isinstance(worst_score, (int, float)):
        worst = f"{worst_score:.1f}/{worst_band or '?'} {worst_identifier}".strip()
    else:
        worst = "—"
    avg_score = cvss.get("average_score")
    avg = f"{avg_score:.1f}" if isinstance(avg_score, (int, float)) else "—"
    counts = cvss.get("band_counts") or {}
    order = ("Critical", "High", "Medium", "Low", "None")
    parts = [f"{label[0]}:{int(counts[label])}" for label in order if counts.get(label)]
    bands = ", ".join(parts) if parts else "—"
    return worst, avg, bands


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
    headers = [
        "Area",
        "High",
        "Med",
        "Low",
        "Info",
        "Status",
        "Risk",
        "Basis",
        "CVSS%",
        "Worst CVSS",
        "Avg",
        "Bands",
        "Controls",
    ]
    table: list[list[str]] = []
    passes = 0
    for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE"):
        entry = next((row for row in rows if row["area"] == area), None)
        if entry is None:
            table.append([
                area.title(),
                "0",
                "0",
                "0",
                "0",
                "PASS",
                "—",
                "—",
                "—",
                "—",
                "—",
                "—",
                "0/0",
            ])
            passes += 1
            continue
        high = entry.get("high", 0)
        medium = entry.get("medium", 0)
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
        worst_cvss, avg_cvss, band_cvss = _format_cvss(entry)
        quality = entry.get("quality") if isinstance(entry, dict) else None
        basis_display = "—"
        if isinstance(quality, dict):
            risk_index = quality.get("risk_index")
            coverage = quality.get("cvss_coverage")
            components = quality.get("risk_components") if isinstance(quality.get("risk_components"), dict) else {}
            inputs = components.get("inputs") if isinstance(components, dict) else {}
            if isinstance(inputs, dict):
                sev = inputs.get("severity_density_norm")
                band = inputs.get("cvss_band_score")
                intensity = inputs.get("cvss_intensity")
                if all(isinstance(val, (int, float)) for val in (sev, band, intensity)):
                    basis_display = f"S{sev:.2f}/B{band:.2f}/I{intensity:.2f}"
        else:
            risk_index = None
            coverage = None
        risk_display = f"{risk_index:.1f}" if isinstance(risk_index, (int, float)) else "—"
        coverage_display = (
            f"{coverage * 100:.0f}%" if isinstance(coverage, (int, float)) else "—"
        )
        table.append([
            area.title(),
            str(high),
            str(medium),
            str(low),
            str(info),
            status,
            risk_display,
            basis_display,
            coverage_display,
            worst_cvss,
            avg_cvss,
            band_cvss,
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

    headers = ["App", "Network", "Platform", "Privacy", "Storage", "Pass %", "Score"]
    areas = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")
    rows: list[list[str]] = []
    total_packages = len(matrix)
    fail_packages = 0
    warn_packages = 0
    aggregate_pass = 0
    pass_rates: list[int] = []
    area_pass_totals: Dict[str, int] = {area: 0 for area in areas}
    score_values: list[float] = []

    def _clip(text: str, limit: int = 44) -> str:
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    ordered_items = sorted(
        matrix.items(),
        key=lambda item: (str(item[1].get("label") or item[0]).lower(), item[0].lower()),
    )

    display_lookup: Dict[str, str] = {}
    alias_lookup: Dict[str, str] = {}

    for package, data in ordered_items:
        display_name = str(data.get("label") or package)
        display_lookup[package] = display_name
        alias_lookup.setdefault(display_name.lower(), package)
        statuses: Dict[str, str] = data["status"]
        counts: Dict[str, Dict[str, int]] = data["counts"]
        pass_rate = data["pass_rate"]
        top_lookup = data.get("top") or {}

        def _fmt(area: str) -> str:
            status = statuses.get(area, "–")
            area_counts = counts.get(area, {"high": 0, "medium": 0, "low": 0, "info": 0})
            top_entry = top_lookup.get(area, {}) if isinstance(top_lookup, dict) else {}
            if status == "FAIL":
                high = area_counts.get("high", 0)
                descriptor = _format_descriptor(top_entry.get("high"), "High")
                parts = [f"FAIL H{high}"]
                if descriptor:
                    parts.append(descriptor)
                text = _clip(" ".join(parts), 50)
                return colors.apply(text, colors.style("error"), bold=True)
            if status == "WARN":
                medium = area_counts.get("medium", 0)
                descriptor = _format_descriptor(top_entry.get("medium"), "Medium")
                parts = [f"WARN M{medium}"]
                if descriptor:
                    parts.append(descriptor)
                text = _clip(" ".join(parts), 50)
                return colors.apply(text, colors.style("warning"), bold=True)
            if status == "PASS":
                total_controls = (
                    area_counts.get("high", 0)
                    + area_counts.get("medium", 0)
                    + area_counts.get("low", 0)
                    + area_counts.get("info", 0)
                )
                descriptor = (
                    f"{total_controls} control{'s' if total_controls != 1 else ''}"
                    if total_controls
                    else "No findings"
                )
                text = _clip(f"PASS {descriptor}", 50)
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
        version_display = ""
        version_name = data.get("version_name")
        if isinstance(version_name, str) and version_name.strip():
            version_display = f" (v{version_name.strip()})"
        target_sdk = data.get("target_sdk")
        if isinstance(target_sdk, int):
            version_display += f" • T{target_sdk}"
        if display_name.lower() != package.lower():
            app_cell = _clip(f"{display_name}{version_display} [{package}]", 64)
        else:
            app_cell = _clip(f"{display_name}{version_display}", 64)

        rows.append(
            [
                app_cell,
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
    menu_utils.print_hint("Data source: MASVS findings persisted in the database (runs/findings tables).", icon="ℹ")
    print()
    print("Legend:")
    print(f"  {colors.apply('PASS', colors.style('success'), bold=True)}  No medium/high findings - contributes 1.0 to score")
    print(f"  {colors.apply('WARN', colors.style('warning'), bold=True)}  Medium findings present - contributes 0.5 to score")
    print(f"  {colors.apply('FAIL', colors.style('error'), bold=True)}  High findings present - contributes 0.0 to score")

    actionable_packages = [
        (package, display_lookup.get(package, package))
        for package, data in ordered_items
        if any(data["status"].get(area) in {"FAIL", "WARN"} for area in areas)
    ]
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
            display_name = display_lookup.get(target, target)
            menu_utils.print_section(f"Matrices - {display_name} ({target})")
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
                    descriptor = _format_descriptor(top_entry.get("high"), "High")
                    if descriptor:
                        descriptor = f"High — {descriptor}"
                    else:
                        descriptor = "High finding present"
                elif status == "WARN":
                    descriptor = _format_descriptor(top_entry.get("medium"), "Medium")
                    if descriptor:
                        descriptor = f"Medium — {descriptor}"
                    else:
                        descriptor = "Medium finding present"
                else:
                    total_ctrls = (
                        counts.get("high", 0)
                        + counts.get("medium", 0)
                        + counts.get("low", 0)
                        + counts.get("info", 0)
                    )
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
            meta_bits: list[str] = []
            version_name = data.get("version_name")
            if isinstance(version_name, str) and version_name.strip():
                meta_bits.append(f"Version: {version_name.strip()}")
            version_code = data.get("version_code")
            if isinstance(version_code, int):
                meta_bits.append(f"Code: {version_code}")
            target_sdk = data.get("target_sdk")
            if isinstance(target_sdk, int):
                meta_bits.append(f"Target SDK: {target_sdk}")
            scope_label = data.get("scope_label")
            if isinstance(scope_label, str) and scope_label.strip():
                meta_bits.append(f"Scope: {scope_label.strip()}")
            session_stamp = data.get("session_stamp")
            if isinstance(session_stamp, str) and session_stamp.strip():
                meta_bits.append(f"Session: {session_stamp.strip()}")
            if meta_bits:
                print(status_messages.status(" | ".join(meta_bits), level="info"))
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
            preview = ", ".join(
                (
                    display if display.lower() == package.lower() else f"{display} ({package})"
                )
                for package, display in actionable_packages[:6]
            )
            choice = prompt_utils.prompt_text(
                "Package to inspect",
                required=False,
                hint=f"Available: {preview}" if actionable_packages else None,
            ).strip()
            if not choice:
                break
            target_pkg = choice if choice in matrix else alias_lookup.get(choice.lower())
            if not target_pkg:
                print(status_messages.status("Package not recognised. Try again.", level="warn"))
                continue
            _render_package_detail(target_pkg)
            seen_any = True
            if not prompt_utils.prompt_yes_no("Inspect another package?", default=False):
                break
        if seen_any:
            print()

    prompt_utils.press_enter_to_continue()


__all__ = ["render_masvs_summary_menu", "render_scoring_explainer_menu", "render_masvs_matrix_menu"]
