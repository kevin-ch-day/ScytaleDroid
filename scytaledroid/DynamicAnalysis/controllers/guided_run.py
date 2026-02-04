"""Guided dataset run controller."""

from __future__ import annotations

from collections.abc import Callable

from scytaledroid.DynamicAnalysis.controllers.device_select import select_device
from scytaledroid.DynamicAnalysis.plan_selection import (
    print_plan_selection_banner,
    resolve_plan_selection,
)
from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages
from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.StaticAnalysis.core.repository import group_artifacts
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def run_guided_dataset_run(
    *,
    select_package_from_groups: Callable[[object, str], str | None],
    select_observers: Callable[[str, str], list[str]],
    print_device_badge: Callable[[str, str], None],
    print_tier1_qa_result: Callable[[str], None] | None = None,
) -> None:
    print()
    menu_utils.print_header("Guided Dataset Run")
    selected = select_device()
    if not selected:
        return
    device_serial, device_label = selected
    print_device_badge(device_serial, device_label)

    scenario_id = "basic_usage"
    duration_seconds = 0
    label = "Dataset (guided)"

    groups = group_artifacts()
    dataset_pkgs = {pkg.lower() for pkg in load_profile_packages("RESEARCH_DATASET_ALPHA")}
    if not dataset_pkgs:
        print(status_messages.status("Research Dataset Alpha profile has no apps.", level="warn"))
        return

    available = {group.package_name.lower() for group in groups if group.package_name}
    scoped_groups = tuple(
        group
        for group in groups
        if group.package_name
        and group.package_name.lower() in available.intersection(dataset_pkgs)
    )
    if not scoped_groups:
        print(
            status_messages.status(
                "No APK artifacts available for Research Dataset Alpha. Pull APKs or use Custom package name.",
                level="warn",
            )
        )
        return

    package_name = select_package_from_groups(scoped_groups, title="Research Dataset Alpha apps")
    if not package_name:
        return

    tier = "dataset"

    print()
    menu_utils.print_header("Dynamic Run Observers")
    observer_ids = select_observers(device_serial, mode="guided")

    if not observer_ids:
        print(status_messages.status("Select at least one observer.", level="error"))
        return

    plan_selection = resolve_plan_selection(package_name)
    if not plan_selection:
        return
    plan_path = plan_selection["plan_path"]
    static_run_id = plan_selection["static_run_id"]
    print_plan_selection_banner(plan_selection)
    clear_logcat = prompt_utils.prompt_yes_no("Clear logcat at run start?", default=True)

    from scytaledroid.DynamicAnalysis.run_dynamic_analysis import run_dynamic_analysis

    result = run_dynamic_analysis(
        package_name,
        duration_seconds=duration_seconds,
        device_serial=device_serial,
        scenario_id=scenario_id,
        observer_ids=tuple(observer_ids),
        interactive=True,
        plan_path=plan_path,
        tier=tier,
        static_run_id=static_run_id,
        clear_logcat=clear_logcat,
    )
    print_run_summary(result, label)
    if result.dynamic_run_id and print_tier1_qa_result:
        print_tier1_qa_result(result.dynamic_run_id)


__all__ = ["run_guided_dataset_run"]
