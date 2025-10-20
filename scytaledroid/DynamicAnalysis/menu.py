"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def dynamic_analysis_menu() -> None:
    options = [
        menu_utils.MenuOption("1", "Launch sandbox run"),
        menu_utils.MenuOption("2", "View recent dynamic sessions"),
        menu_utils.MenuOption("3", "Configure instrumentation"),
    ]

    while True:
        print()
        menu_utils.print_header("Dynamic Analysis")
        menu_utils.print_menu(options, is_main=False, show_exit=True, exit_label="Back")
        choice = prompt_utils.get_choice([option.key for option in options] + ["0"])

        if choice == "0":
            break

        print(status_messages.status("Dynamic analysis workflow not implemented yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
