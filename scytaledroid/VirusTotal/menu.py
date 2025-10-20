"""VirusTotal analysis menu placeholder."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def virustotal_menu() -> None:
    options = [
        menu_utils.MenuOption("1", "Submit hash for quick lookup"),
        menu_utils.MenuOption("2", "Submit file for analysis"),
        menu_utils.MenuOption("3", "View recent submissions"),
    ]

    while True:
        print()
        menu_utils.print_header("VirusTotal Analysis")
        menu_utils.print_menu(options, is_main=False, show_exit=True, exit_label="Back")
        choice = prompt_utils.get_choice([option.key for option in options] + ["0"])

        if choice == "0":
            break

        print(status_messages.status("Feature not yet implemented", level="warn"))
        prompt_utils.press_enter_to_continue()
