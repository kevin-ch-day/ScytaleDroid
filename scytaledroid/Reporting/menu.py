"""Reporting menu scaffolding."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages


def reporting_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Reporting")
        options = {
            "1": "Generate device summary report",
            "2": "Generate APK analysis report",
            "3": "View saved reports",
        }
        menu_utils.print_menu(options, is_main=False)
        choice = menu_utils.get_choice(list(options.keys()) + ["0"])

        if choice == "0":
            break

        print(status_messages.status("Reporting workflow not implemented yet.", level="warn"))
        menu_utils.press_enter_to_continue()
