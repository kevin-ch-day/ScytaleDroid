"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def dynamic_analysis_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Dynamic Analysis")
        options = {
            "1": "Launch sandbox run",
            "2": "View recent dynamic sessions",
            "3": "Configure instrumentation",
        }
        menu_utils.print_menu(options, is_main=False)
        choice = prompt_utils.get_choice(list(options.keys()) + ["0"])

        if choice == "0":
            break

        print(status_messages.status("Dynamic analysis workflow not implemented yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
