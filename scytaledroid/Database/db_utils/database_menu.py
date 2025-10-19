"""Top-level Database Utilities menu."""

from __future__ import annotations

from typing import List, Tuple

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils import permission_catalog
from scytaledroid.Database.db_utils.menus import health_checks, query_runner, runs_dashboard, schema_browser
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def database_menu() -> None:
    """Render the database utilities menu and dispatch to sub-menus."""

    while True:
        _maybe_clear_screen()
        menu_utils.print_header("Database Utilities")

        options: List[Tuple[str, str, str]] = [
            ("1", "Check connection & show config", "Verify connectivity and display active parameters."),
            ("2", "Schema snapshot / browser", "Explore schema groups with indexes and sample rows."),
            ("3", "Data health checks (ingestion & scoring)", "Run deterministic ingestion & scoring checks."),
            ("4", "Recent runs dashboard", "Summarise the latest runs and key metrics."),
            ("5", "Run database queries", "Quick checks to validate static-analysis persistence."),
            ("6", "Refresh framework permission catalog", "Load/update android_framework_permissions from config."),
            ("7", "Reset static analysis data", "Truncate derived static-analysis tables (destructive)."),
            ("0", "Back", "Return to the previous menu."),
        ]
        menu_utils.print_menu(options, padding=True, show_exit=False)
        choice = prompt_utils.get_choice(valid=[opt[0] for opt in options])

        if choice == "1":
            _handle_check_connection_and_config()
        elif choice == "2":
            schema_browser.show_schema_browser()
        elif choice == "3":
            health_checks.run_health_checks()
        elif choice == "4":
            runs_dashboard.show_recent_runs_dashboard()
        elif choice == "5":
            query_runner.run_query_menu()
        elif choice == "6":
            permission_catalog.refresh_framework_catalog()
            prompt_utils.press_enter_to_continue()
        elif choice == "7":
            health_checks.prompt_reset_static_data()
        elif choice == "0":
            break


def _handle_check_connection_and_config() -> None:
    """Display DB configuration and test the connection."""

    try:
        from scytaledroid.Database.db_core import db_config as _dbc

        cfg = _dbc.DB_CONFIG
        host = str(cfg.get("host", "<unknown>"))
        port_display = str(cfg.get("port", "<unknown>"))
        database = str(cfg.get("database", "<unknown>"))
        user = str(cfg.get("user", "<unknown>"))
    except Exception as exc:
        host = port_display = database = user = "<unknown>"
        print(status_messages.status(f"Unable to read DB config: {exc}", level="warn"))

    def _section(title: str) -> None:
        print(title)
        print("-" * len(title))

    _section("Database Configuration")
    print(f"    Host:       {host}")
    print(f"    Port:       {port_display}")
    print(f"    Database:   {database}")
    print(f"    Username:   {user}")
    print()

    _section("Test Database Connection")
    success = diagnostics.check_connection()
    if success:
        print("    Connection established successfully")
    else:
        print("    Connection failed. Check logs for details.")
    prompt_utils.press_enter_to_continue()


def _maybe_clear_screen() -> None:
    try:
        from scytaledroid.Utils.DisplayUtils import ui_prefs as _ui

        if _ui.should_clear():
            from scytaledroid.Utils.System.util_actions import clear_screen as _clear

            _clear()
        else:
            print()
    except Exception:
        print()


if __name__ == "__main__":  # pragma: no cover
    database_menu()
