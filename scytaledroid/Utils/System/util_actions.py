"""util_actions.py - Standalone utility actions for the system menu."""

from __future__ import annotations

import os

from scytaledroid.Utils.DisplayUtils import status_messages


def clear_screen() -> None:
    """Clear the terminal window."""

    os.system("cls" if os.name == "nt" else "clear")
    print(status_messages.status("Screen cleared.", level="info"))


def show_log_locations() -> None:
    """Display key log locations for quick reference."""

    print(status_messages.status("Application logs: ./logs/application.log", level="info"))
    print(status_messages.status("Device analysis logs: ./logs/device_analysis.log", level="info"))
    print(status_messages.status("Command history / state: ./data/state/", level="info"))


__all__ = ["clear_screen", "show_log_locations"]
