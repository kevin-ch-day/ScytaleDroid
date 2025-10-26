"""Top-level Database Utilities menu."""

from __future__ import annotations

from typing import Callable, Dict, List

from scytaledroid.Database.db_utils.menus import (
    health_checks,
    query_runner,
    schema_browser,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils

from .menu_actions import (
    maybe_clear_screen,
    show_connection_and_config,
)


def database_menu() -> None:
    """Render the database utilities menu and dispatch to sub-menus."""

    actions: Dict[str, Callable[[], None]] = {
        "1": show_connection_and_config,
        "2": schema_browser.show_schema_browser,
        "3": query_runner.run_query_menu,
        "4": health_checks.prompt_reset_static_data,
    }

    options: List[menu_utils.MenuOption] = [
        menu_utils.MenuOption(
            "1",
            "Check connection & show config",
            "Verify connectivity and display active parameters.",
        ),
        menu_utils.MenuOption(
            "2",
            "Schema snapshot / browser",
            "Explore schema groups with indexes and sample rows.",
        ),
        menu_utils.MenuOption(
            "3",
            "Run database queries",
            "Quick checks to validate static-analysis persistence.",
        ),
        menu_utils.MenuOption(
            "4",
            "Reset static analysis data",
            "Truncate derived static-analysis tables (destructive).",
        ),
    ]

    while True:
        maybe_clear_screen()
        menu_utils.print_header("Database Utilities")
        menu_utils.print_menu(options, padding=True, show_exit=True, exit_label="Back")

        choice = prompt_utils.get_choice([option.key for option in options] + ["0"])

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            action()


if __name__ == "__main__":  # pragma: no cover
    database_menu()
