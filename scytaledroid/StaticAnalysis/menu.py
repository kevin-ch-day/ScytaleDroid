"""Static analysis menu scaffolding."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def static_analysis_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Static Analysis")
        options = {
            "1": "Analyze APK from repository",
            "2": "Upload new APK for analysis",
            "3": "Review past analysis reports",
        }
        menu_utils.print_menu(options, is_main=False)
        choice = prompt_utils.get_choice(list(options.keys()) + ["0"])

        if choice == "0":
            break

        print(status_messages.status("Static analysis workflow not implemented yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
