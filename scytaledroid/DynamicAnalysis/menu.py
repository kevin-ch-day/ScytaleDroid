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

        print(status_messages.status("Dynamic analysis workflow not implemented yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
