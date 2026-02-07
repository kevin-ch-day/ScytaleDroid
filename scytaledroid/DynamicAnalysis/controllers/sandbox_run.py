"""Sandbox run controller for dynamic analysis."""

from __future__ import annotations

import os
from collections.abc import Callable

from scytaledroid.DynamicAnalysis.controllers.device_select import select_device
from scytaledroid.DynamicAnalysis.plan_selection import (
    print_plan_selection_banner,
    resolve_plan_selection,
)
from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def run_sandbox_dynamic_run(
    *,
    select_dynamic_target: Callable[[], tuple[str, str] | None],
    select_observers: Callable[[str, str], list[str]],
    print_root_status: Callable[[str], bool],
    print_network_status: Callable[[str], None],
) -> None:
    print()
    selected = select_device()
    if not selected:
        return
    device_serial, _device_label = selected
    print_root_status(device_serial)
    print_network_status(device_serial)
    print()
    scenario_id = "basic_usage"
    duration_seconds = 0
    label = "Manual"
    menu_utils.print_header("Dynamic Run Scenario")
    print(status_messages.status("Tip: Basic usage is recommended for validation runs.", level="info"))
    scenario_options = [
        menu_utils.MenuOption("1", "Cold start"),
        menu_utils.MenuOption("2", "Basic usage"),
        menu_utils.MenuOption("3", "Permission trigger"),
    ]
    scenario_spec = menu_utils.MenuSpec(items=scenario_options, exit_label="Cancel", show_exit=True)
    menu_utils.render_menu(scenario_spec)
    scenario_choice = prompt_utils.get_choice(
        [option.key for option in scenario_options] + ["0"],
        default="2",
    )
    if scenario_choice == "0":
        return
    scenario_id = {"1": "cold_start", "2": "basic_usage", "3": "permission_trigger"}.get(
        scenario_choice,
        "basic_usage",
    )
    selection = select_dynamic_target()
    package_name = selection[0] if selection else None
    tier = selection[1] if selection else "exploration"
    if tier == "dataset":
        if prompt_utils.prompt_yes_no("Run as exploration instead of dataset?", default=False):
            tier = "exploration"
    elif package_name == "com.zhiliaoapp.musically":
        if prompt_utils.prompt_yes_no("Mark this run as calibration?", default=True):
            tier = "calibration"
    if not package_name:
        return
    print()
    menu_utils.print_header("Dynamic Run Observers")
    observer_ids = select_observers(device_serial, mode="sandbox")
    if not observer_ids:
        print(status_messages.status("Select at least one observer.", level="error"))
        prompt_utils.press_enter_to_continue()
        return
    try:
        plan_selection = resolve_plan_selection(package_name)
    except Exception as exc:  # noqa: BLE001
        print(
            status_messages.status(
                f"Baseline selection unavailable (error: {exc}).",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return
    if not plan_selection:
        prompt_utils.press_enter_to_continue()
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
        require_dynamic_schema=True,
        observer_prompts_enabled=(os.environ.get("SCYTALEDROID_OBSERVER_PROMPTS") == "1"),
        pcapdroid_api_key=os.environ.get("SCYTALEDROID_PCAPDROID_API_KEY"),
    )
    print_run_summary(result, label)
    prompt_utils.press_enter_to_continue()


__all__ = ["run_sandbox_dynamic_run"]
