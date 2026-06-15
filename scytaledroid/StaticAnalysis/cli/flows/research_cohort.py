"""DB-backed research cohort selection for static analysis."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.Database.db_func.research_cohorts import (
    fetch_active_research_cohort_members,
    fetch_research_cohort,
    list_active_research_cohorts,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from ...core.repository import load_display_name_map
from ..core.models import ScopeSelection
from .profile_prior_session import fetch_prior_profile_session_snapshot
from .selection import (
    _collapse_latest_by_package,
    _print_prior_profile_session_snapshot,
    _print_workload_summary_lines,
    _render_profile_selection_table,
)


@dataclass(frozen=True)
class ResearchCohortPreparedSelection:
    cohort_key: str
    display_name: str
    description: str | None
    package_names: tuple[str, ...]
    missing_packages: tuple[str, ...]
    selection: ScopeSelection
    total_apk_files: int
    base_apk_count: int
    split_apk_count: int
    largest_split_heavy_apps: tuple[tuple[str, str, int], ...]


def _largest_split_groups(selection: ScopeSelection) -> tuple[tuple[str, str, int], ...]:
    display_map = load_display_name_map(selection.groups)
    rows: list[tuple[str, str, int]] = []
    for group in selection.groups:
        total = len(getattr(group, "artifacts", ()) or ())
        rows.append(
            (
                display_map.get(str(getattr(group, "package_name", "") or "").lower(), str(getattr(group, "package_name", "") or "")),
                str(getattr(group, "package_name", "") or ""),
                total,
            )
        )
    rows.sort(key=lambda row: row[2], reverse=True)
    return tuple(rows[:5])


def _selection_counts(selection: ScopeSelection) -> tuple[int, int, int]:
    total = 0
    split_total = 0
    for group in selection.groups:
        total += len(getattr(group, "artifacts", ()) or ())
        split_total += sum(1 for artifact in getattr(group, "artifacts", ()) or () if getattr(artifact, "is_split_member", False))
    return total, total - split_total, split_total


def prepare_research_cohort_scope(groups: tuple, cohort_key: str) -> ResearchCohortPreparedSelection | None:
    cohort = fetch_research_cohort(cohort_key)
    if not cohort:
        return None
    members = fetch_active_research_cohort_members(cohort_key)
    package_names = tuple(
        str(row.get("package_name") or "").strip().lower()
        for row in members
        if str(row.get("package_name") or "").strip()
    )
    if not package_names:
        selection = ScopeSelection(
            scope="research_cohort",
            label=str(cohort.get("display_name") or cohort_key),
            groups=tuple(),
            selection_rule_summary="Newest harvest capture per package",
        )
        return ResearchCohortPreparedSelection(
            cohort_key=str(cohort.get("cohort_key") or cohort_key),
            display_name=str(cohort.get("display_name") or cohort_key),
            description=str(cohort.get("description") or "").strip() or None,
            package_names=tuple(),
            missing_packages=tuple(),
            selection=selection,
            total_apk_files=0,
            base_apk_count=0,
            split_apk_count=0,
            largest_split_heavy_apps=tuple(),
        )

    ordered_groups: list[object] = []
    missing_packages: list[str] = []
    older_excluded = 0
    for package_name in package_names:
        matching = [group for group in groups if str(getattr(group, "package_name", "") or "").strip().lower() == package_name]
        if not matching:
            missing_packages.append(package_name)
            continue
        _grouped, selected, _skipped_details = _collapse_latest_by_package(tuple(matching))
        older_excluded += max(len(matching) - len(selected), 0)
        ordered_groups.extend(selected)
    scoped = tuple(ordered_groups)
    selection = ScopeSelection(
        scope="research_cohort",
        label=str(cohort.get("display_name") or cohort_key),
        groups=scoped,
        older_captures_excluded=older_excluded,
        selection_rule_summary="Newest harvest capture per package",
    )
    total_apk_files, base_apk_count, split_apk_count = _selection_counts(selection)
    return ResearchCohortPreparedSelection(
        cohort_key=str(cohort.get("cohort_key") or cohort_key),
        display_name=str(cohort.get("display_name") or cohort_key),
        description=str(cohort.get("description") or "").strip() or None,
        package_names=package_names,
        missing_packages=tuple(missing_packages),
        selection=selection,
        total_apk_files=total_apk_files,
        base_apk_count=base_apk_count,
        split_apk_count=split_apk_count,
        largest_split_heavy_apps=_largest_split_groups(selection),
    )


def render_research_cohort_workload(prepared: ResearchCohortPreparedSelection) -> ScopeSelection:
    selection = prepared.selection

    print()
    menu_utils.print_header(
        "Static Analysis · Research Cohort Workload",
        "Review the cohort list; final package and APK totals are in Run Setup.",
    )
    _print_workload_summary_lines(
        profile_title=prepared.display_name,
        scoped=selection.groups,
        older_excluded=selection.older_captures_excluded,
        rule_line=selection.selection_rule_summary or "Newest harvest capture per package",
        scope_noun="Research cohort",
    )
    _print_prior_profile_session_snapshot(
        fetch_prior_profile_session_snapshot(prepared.display_name, frozenset(prepared.package_names))
    )
    print()
    _render_profile_selection_table(selection.groups)
    if prepared.missing_packages:
        print()
        print(
            status_messages.status(
                "Missing from harvested library: " + ", ".join(prepared.missing_packages),
                level="warn",
            )
        )
    print()
    print("Final package and APK totals depend on preset and split scan settings; Run Setup shows the exact counts.")
    return selection


def choose_research_cohort_scope(groups: tuple) -> ScopeSelection | None:
    cohorts = list_active_research_cohorts()
    if not cohorts:
        print(status_messages.status("No active research cohorts are defined in the DB.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return None

    print()
    menu_utils.print_header(
        "Static Analysis · Select Research Cohort",
        "Research cohorts are DB-backed reusable datasets. Runs use the newest harvest per app.",
    )
    rows = [
        [str(idx), str(row.get("display_name") or row.get("cohort_key") or ""), str(int(row.get("active_member_count") or 0))]
        for idx, row in enumerate(cohorts, start=1)
    ]
    table_utils.render_table(["#", "Research cohort", "Apps"], rows, compact=True, padding=2)
    print()
    print(f"Research cohorts: {len(rows)}")
    choice = prompt_utils.get_choice([str(index) for index in range(1, len(rows) + 1)] + ["0"], default="1")
    if choice == "0":
        return None
    row = cohorts[int(choice) - 1]
    prepared = prepare_research_cohort_scope(groups, str(row.get("cohort_key") or ""))
    if prepared is None:
        print(status_messages.status("Failed to load the selected research cohort.", level="error"))
        prompt_utils.press_enter_to_continue()
        return None
    return render_research_cohort_workload(prepared)


__all__ = [
    "ResearchCohortPreparedSelection",
    "choose_research_cohort_scope",
    "prepare_research_cohort_scope",
    "render_research_cohort_workload",
]
