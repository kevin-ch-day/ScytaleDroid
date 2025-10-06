"""
main.py - Entry point for ScytaleDroid CLI
"""

from datetime import datetime
import zoneinfo
from typing import Dict

from scytaledroid.Config import app_config
from scytaledroid.Utils.AboutApp.about_app import about_app
from scytaledroid.DeviceAnalysis.device_analysis_menu import device_menu
from scytaledroid.Reporting.menu import reporting_menu
from scytaledroid.StaticAnalysis.menu import static_analysis_menu
from scytaledroid.DynamicAnalysis.menu import dynamic_analysis_menu
from scytaledroid.VirusTotal.menu import virustotal_menu
from scytaledroid.Utils.System.utils_menu import utils_menu
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Database.db_utils.menu import database_menu


def _resolve_timezones() -> Dict[str, str]:
    base = dict(getattr(app_config, "DEFAULT_UI_TIMEZONES", {}))
    custom = dict(getattr(app_config, "UI_TIMEZONES", {}))

    # Validate custom entries and fall back to defaults as needed
    validated: Dict[str, str] = {}
    for label, tz in custom.items():
        try:
            zoneinfo.ZoneInfo(tz)
        except Exception:
            log.warning(f"Invalid timezone '{tz}' for label '{label}'", category="application")
            continue
        validated[str(label)] = str(tz)

    max_clocks = getattr(app_config, "UI_MAX_CLOCKS", 3)
    if len(validated) > max_clocks:
        validated = dict(list(validated.items())[:max_clocks])

    if not validated:
        validated = dict(list(base.items())[:max_clocks])

    primary = getattr(app_config, "UI_PRIMARY_CLOCK", None)
    ordered: Dict[str, str] = {}

    if primary and primary in validated:
        ordered[primary] = validated.pop(primary)

    for label, tz in validated.items():
        ordered[label] = tz

    return ordered


def _format_time(tz_name: str) -> str:
    tz = zoneinfo.ZoneInfo(tz_name)
    now = datetime.now(tz)
    time_part = now.strftime("%I:%M %p").lstrip("0")
    date_part = f"{now.month}-{now.day}-{now.year}"
    tz_label = now.tzname() or tz_name
    return f"{date_part} {time_part} {tz_label}".strip()


def print_banner() -> None:
    """Display welcome banner with app metadata and world clock."""

    menu_utils.print_banner(
        app_config.APP_NAME,
        app_config.APP_VERSION,
        app_config.APP_RELEASE,
        app_config.APP_DESCRIPTION,
    )

    tz_mapping = _resolve_timezones()
    metrics = []
    for label, tz_name in tz_mapping.items():
        try:
            metrics.append((label, _format_time(tz_name)))
        except Exception as exc:
            log.warning(f"Failed to render time for {label}: {exc}", category="application")
    if metrics:
        menu_utils.print_metrics(metrics)
    print()

    log.info(
        f"Application started - {app_config.APP_NAME} {app_config.APP_VERSION} ({app_config.APP_RELEASE})",
        category="application",
    )


def main_menu() -> None:
    """Render the main menu loop using the shared menu framework."""
    while True:
        menu_utils.print_header("Main Menu")
        options = [
            menu_utils.MenuOption("1", "Connect to Android Device", "Manage connected devices, inventory, and pulls"),
            menu_utils.MenuOption("2", "VirusTotal analysis", "Look up hashes and APKs against VirusTotal"),
            menu_utils.MenuOption("3", "Static analysis", "Run static checks on harvested applications"),
            menu_utils.MenuOption("4", "Dynamic analysis", "Launch runtime instrumentation workflows"),
            menu_utils.MenuOption("5", "Reporting", "Generate device and artifact reports"),
            menu_utils.MenuOption("6", "Database tools", "Inspect schema, check connection, and view counts"),
            menu_utils.MenuOption("7", "Utilities", "Console helpers and configuration"),
            menu_utils.MenuOption("8", "About App", "Show version and licensing information"),
        ]
        menu_utils.print_menu(options, is_main=True, boxed=False, default="1")
        choice = prompt_utils.get_choice(valid=[opt.key for opt in options] + ["0"], default="1")

        if choice == "1":
            log.info("User selected: Connect to Android Device", category="application")
            handle_device()
        elif choice == "2":
            log.info("User selected: VirusTotal analysis", category="application")
            handle_virustotal()
        elif choice == "3":
            log.info("User selected: Static analysis", category="application")
            handle_static()
        elif choice == "4":
            log.info("User selected: Dynamic analysis", category="application")
            handle_dynamic()
        elif choice == "5":
            log.info("User selected: Reporting", category="application")
            handle_reporting()
        elif choice == "6":
            log.info("User selected: Database tools", category="application")
            handle_database()
        elif choice == "7":
            log.info("User selected: Utils", category="application")
            handle_utils()
        elif choice == "8":
            log.info("User selected: About App", category="application")
            handle_about()
        elif choice == "0":
            log.info("Application shutting down", category="application")
            print("Goodbye!")
            break
        else:
            log.warning(f"Invalid menu choice: {choice}", category="application")
            print("Invalid choice. Please try again.")


# --- Handlers for each menu option ---

def handle_device() -> None:
    """Launch the Device Analysis menu."""
    device_menu()


def handle_virustotal() -> None:
    virustotal_menu()


def handle_static() -> None:
    static_analysis_menu()


def handle_dynamic() -> None:
    dynamic_analysis_menu()


def handle_reporting() -> None:
    reporting_menu()


def handle_database() -> None:
    database_menu()


def handle_utils() -> None:
    utils_menu()


def handle_about() -> None:
    about_app()


if __name__ == "__main__":
    print_banner()
    main_menu()
