"""
main.py - Entry point for ScytaleDroid CLI
"""

from datetime import datetime
import zoneinfo

from scytaledroid.Config import app_config
from scytaledroid.Utils.AboutApp.about_app import about_app
from scytaledroid.DeviceAnalysis.device_analysis_menu import device_menu
from scytaledroid.Reporting.menu import reporting_menu
from scytaledroid.StaticAnalysis.cli import static_analysis_menu
from scytaledroid.DynamicAnalysis.menu import dynamic_analysis_menu
from scytaledroid.VirusTotal.menu import virustotal_menu
from scytaledroid.Utils.System.utils_menu import utils_menu
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Database.db_utils.menu import database_menu
from scytaledroid.Utils.System.world_clock.state import ClockReference, WorldClockState, load_state


def _resolve_timezones() -> WorldClockState:
    return load_state()


def _format_time(tz_name: str, reference: ClockReference) -> str:
    tz = zoneinfo.ZoneInfo(tz_name)
    snapshot = reference.utc.astimezone(tz)
    time_part = snapshot.strftime("%I:%M %p").lstrip("0")
    date_part = f"{snapshot.month}-{snapshot.day}-{snapshot.year}"
    tz_label = snapshot.tzname() or tz_name
    dst_delta = tz.dst(snapshot)
    dst_active = bool(dst_delta and dst_delta.total_seconds())
    dst_label = "DST" if dst_active else "Std"
    return f"{date_part} {time_part} {tz_label} ({dst_label})"


def _reference_banner(reference: ClockReference) -> str:
    tz_name = reference.timezone or app_config.UI_LOCAL_TIMEZONE or "Etc/UTC"
    try:
        tz = zoneinfo.ZoneInfo(tz_name)
    except Exception:
        tz = zoneinfo.ZoneInfo("UTC")
        tz_name = "UTC"

    localized = reference.utc.astimezone(tz)
    date_part = f"{localized.month}-{localized.day}-{localized.year}"
    time_part = localized.strftime("%I:%M %p").lstrip("0")
    offset_label = localized.tzname() or tz_name
    prefix = "Custom reference" if reference.mode == "custom" else "Live reference"
    label = reference.label or "Live (current time)"
    return f"{prefix}: {label} — {date_part} {time_part} {offset_label}"


def print_banner() -> None:
    """Display welcome banner with app metadata and world clock."""

    menu_utils.print_banner(
        app_config.APP_NAME,
        app_config.APP_VERSION,
        app_config.APP_RELEASE,
        app_config.APP_DESCRIPTION,
    )

    state = _resolve_timezones()
    tz_mapping = state.clocks
    metrics = []
    for label, tz_name in tz_mapping.items():
        try:
            metrics.append((label, _format_time(tz_name, state.reference)))
        except Exception as exc:
            log.warning(f"Failed to render time for {label}: {exc}", category="application")
    if metrics:
        menu_utils.print_metrics(metrics)
        print(
            status_messages.status(
                _reference_banner(state.reference),
                level="info",
            )
        )
    print()

    log.info(
        f"Application started - {app_config.APP_NAME} {app_config.APP_VERSION} ({app_config.APP_RELEASE})",
        category="application",
    )


def main_menu() -> None:
    """Render the main menu loop using the shared menu framework."""
    while True:
        print()
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
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")
        log.info("Application interrupted by user.", category="application")
