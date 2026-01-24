"""Diagnostics and verification helpers for the static analysis CLI."""

from __future__ import annotations

from scytaledroid.Database.db_utils.menus import query_runner
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def render_static_diagnostics_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Static Analysis Diagnostics")
        options = {
            "1": "Latest session snapshot",
            "2": "Session table counts",
            "3": "Runs and buckets by package",
            "4": "Harvest artifacts by package",
        }
        menu_utils.print_menu(options, padding=True, show_exit=False)
        choice = prompt_utils.get_choice(list(options.keys()) + ["0"])

        if choice == "0":
            break
        if choice == "1":
            query_runner.show_latest_session()
        elif choice == "2":
            query_runner.prompt_session_counts()
        elif choice == "3":
            query_runner.prompt_runs_for_package()
        elif choice == "4":
            query_runner.prompt_harvest_for_package()
        else:
            print(status_messages.status("Option not implemented yet.", level="warn"))


__all__ = ["render_static_diagnostics_menu"]
