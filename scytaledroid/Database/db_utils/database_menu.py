"""Top-level Database Utilities menu."""

from __future__ import annotations

from typing import Callable, Dict, List

from scytaledroid.Database.db_utils.menus import (
    health_checks,
    query_runner,
    schema_browser,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from .menu_actions import (
    maybe_clear_screen,
    show_connection_and_config,
    show_db_status,
)
from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_core import db_config


def database_menu() -> None:
    """Render the database utilities menu and dispatch to sub-menus."""

    actions: Dict[str, Callable[[], None]] = {
        "1": show_connection_and_config,
        "2": schema_browser.show_schema_browser,
        "3": query_runner.run_query_menu,
        "4": health_checks.run_health_checks,
        "5": health_checks.prompt_cleanup_orphan_inventory,
        "6": health_checks.prompt_reset_static_data,
        "7": show_db_status,
    }

    options: List[MenuOption] = [
        MenuOption(
            "1",
            "Check connection & show config",
            "Verify connectivity and display active parameters.",
        ),
        MenuOption(
            "2",
            "Schema snapshot / browser",
            "Explore schema groups with indexes and sample rows.",
        ),
        MenuOption(
            "3",
            "Run database queries",
            "Quick checks to validate static-analysis persistence.",
        ),
        MenuOption(
            "4",
            "Run health checks",
            "Quick verification across ingestion + inventory.",
        ),
        MenuOption(
            "5",
            "Cleanup orphan inventory snapshots",
            "Delete snapshot headers that have zero inventory rows.",
        ),
        MenuOption(
            "6",
            "Reset static analysis data",
            "Truncate derived static-analysis tables (destructive).",
        ),
        MenuOption(
            "7",
            "DB status (backend/schema)",
            "Quick view of backend, schema_version, and config source.",
        ),
    ]

    while True:
        maybe_clear_screen()
        cfg = db_config.DB_CONFIG
        backend = str(cfg.get("engine", "sqlite"))
        database = str(cfg.get("database", "<unknown>"))
        host = str(cfg.get("host", "<local>"))
        schema_ver = diagnostics.get_schema_version() or "<unknown>"
        menu_utils.print_header("Database Utilities")
        print(f"[Backend: {backend} | DB: {database} | Host: {host} | Schema: {schema_ver}]")
        spec = MenuSpec(
            items=options,
            exit_label="Back",
            padding=True,
            show_exit=True,
        )
        menu_utils.render_menu(spec)

        choice = prompt_utils.get_choice([option.key for option in options] + ["0"], default="1")

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            action()


if __name__ == "__main__":  # pragma: no cover
    database_menu()
