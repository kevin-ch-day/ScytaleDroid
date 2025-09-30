"""VirusTotal analysis menu placeholder."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def virustotal_menu() -> None:
    while True:
        print()
        menu_utils.print_header("VirusTotal Analysis")
        options = {
            "1": "Submit hash for quick lookup",
            "2": "Submit file for analysis",
            "3": "View recent submissions",
        }
        menu_utils.print_menu(options, is_main=False)
        choice = prompt_utils.get_choice(list(options.keys()) + ["0"])

        if choice == "0":
            break

        print(status_messages.status("Feature not yet implemented", level="warn"))
        prompt_utils.press_enter_to_continue()
