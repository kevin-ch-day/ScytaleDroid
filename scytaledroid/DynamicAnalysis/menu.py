"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

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
