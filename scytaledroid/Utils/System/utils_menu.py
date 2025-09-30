"""Utility menu actions for Scytaledroid CLI."""

from __future__ import annotations

import os
from typing import Callable, Dict

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def utils_menu() -> None:
    actions: Dict[str, Callable[[], None]] = {
        "1": clear_screen,
        "2": show_log_locations,
    }
    labels = {
        "1": "Clear the console",
        "2": "Show log directories",
    }

    while True:
        print()
        menu_utils.print_header("Utilities")
        menu_utils.print_menu(labels, is_main=False)
        choice = prompt_utils.get_choice(list(labels.keys()) + ["0"])

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            action()
        else:
            print(status_messages.status("Action not available.", level="warn"))
        prompt_utils.press_enter_to_continue()


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")
    print(status_messages.status("Screen cleared.", level="info"))


def show_log_locations() -> None:
    print(status_messages.status("Log directories", level="info"))
    print("  - Application logs: ./logs/application.log")
    print("  - Device analysis logs: ./logs/device_analysis.log")
    print("  - Command history / state: ./data/state/")


__all__ = ["utils_menu"]
