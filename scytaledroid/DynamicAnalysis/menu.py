"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis import adb_utils
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec


def dynamic_analysis_menu() -> None:
    options = [
        MenuOption("1", "Launch sandbox run"),
        MenuOption("2", "View recent dynamic sessions"),
        MenuOption("3", "Configure instrumentation"),
    ]

    while True:
        print()
        menu_utils.print_header("Dynamic Analysis")
        spec = MenuSpec(items=options, exit_label="Back", show_exit=True)
        menu_utils.render_menu(spec)
        choice = prompt_utils.get_choice([option.key for option in options] + ["0"])

        if choice == "0":
            break

        if choice == "1":
            print()
            menu_utils.print_header("Dynamic Run Device")
            devices, warnings = adb_utils.scan_devices()
            for warning in warnings:
                print(status_messages.status(warning, level="warn"))
            if not devices:
                print(status_messages.status("No devices detected via adb.", level="error"))
                prompt_utils.press_enter_to_continue()
                continue
            device_options = [
                MenuOption(str(index + 1), adb_utils.get_device_label(device))
                for index, device in enumerate(devices)
            ]
            device_spec = MenuSpec(items=device_options, exit_label="Cancel", show_exit=True)
            menu_utils.render_menu(device_spec)
            device_choice = prompt_utils.get_choice(
                [option.key for option in device_options] + ["0"],
                default="1",
            )
            if device_choice == "0":
                continue
            device_index = int(device_choice) - 1
            device_serial = devices[device_index].get("serial")
            if not device_serial:
                print(status_messages.status("Selected device missing serial.", level="error"))
                prompt_utils.press_enter_to_continue()
                continue
            print()
            menu_utils.print_header("Dynamic Run Scenario")
            scenario_options = [
                MenuOption("1", "Cold start"),
                MenuOption("2", "Basic usage"),
                MenuOption("3", "Permission trigger"),
            ]
            scenario_spec = MenuSpec(items=scenario_options, exit_label="Cancel", show_exit=True)
            menu_utils.render_menu(scenario_spec)
            scenario_choice = prompt_utils.get_choice(
                [option.key for option in scenario_options] + ["0"],
                default="2",
            )
            if scenario_choice == "0":
                continue
            scenario_id = {"1": "cold_start", "2": "basic_usage", "3": "permission_trigger"}.get(
                scenario_choice,
                "basic_usage",
            )
            print()
            menu_utils.print_header("Dynamic Run Observers")
            use_network = prompt_utils.prompt_yes_no("Enable network capture?", default=True)
            use_logs = prompt_utils.prompt_yes_no("Enable system log capture?", default=True)
            observer_ids = []
            if use_network:
                observer_ids.append("network_capture")
            if use_logs:
                observer_ids.append("system_log_capture")
            if not observer_ids:
                print(status_messages.status("Select at least one observer.", level="error"))
                prompt_utils.press_enter_to_continue()
                continue
            print()
            menu_utils.print_header("Dynamic Run Duration")
            duration_options = [
                MenuOption("1", "Short (90s)"),
                MenuOption("2", "Standard (120s)"),
                MenuOption("3", "Extended (180s)"),
            ]
            duration_spec = MenuSpec(items=duration_options, exit_label="Cancel", show_exit=True)
            menu_utils.render_menu(duration_spec)
            selection = prompt_utils.get_choice(["1", "2", "3", "0"], default="2")
            if selection == "0":
                continue
            duration_map = {"1": 90, "2": 120, "3": 180}
            duration_seconds = duration_map.get(selection, 120)
            label = {
                "1": "Short",
                "2": "Standard",
                "3": "Extended",
            }.get(selection, "Standard")
            package_name = prompt_utils.prompt_text(
                "Package name",
                required=True,
                error_message="Please provide a package name.",
            )
            from .run_dynamic_analysis import run_dynamic_analysis

            result = run_dynamic_analysis(
                package_name,
                duration_seconds=duration_seconds,
                device_serial=device_serial,
                scenario_id=scenario_id,
                observer_ids=tuple(observer_ids),
                interactive=True,
            )
            message = (
                f"Selected duration: {label} ({duration_seconds}s). "
                f"Session status: {result.status}."
            )
            print(status_messages.status(message, level="warn"))
            prompt_utils.press_enter_to_continue()
            continue

        print(status_messages.status("Dynamic analysis workflow not implemented yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
