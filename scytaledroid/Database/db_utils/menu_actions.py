"""Helper actions for the database utilities menu."""

from __future__ import annotations

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages


def show_connection_and_config() -> None:
    """Display database configuration details and test connectivity."""

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


def maybe_clear_screen() -> None:
    """Clear the terminal when UI preferences request it."""

    try:
        from scytaledroid.Utils.DisplayUtils import ui_prefs as _ui

        if _ui.should_clear():
            from scytaledroid.Utils.System.util_actions import clear_screen as _clear

            _clear()
        else:
            print()
    except Exception:
        print()


__all__ = [
    "maybe_clear_screen",
    "show_connection_and_config",
]
