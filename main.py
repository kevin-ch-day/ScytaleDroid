"""
main.py - Entry point for ScytaleDroid CLI
"""

from datetime import datetime
import zoneinfo

from scytaledroid.Config import app_config
from scytaledroid.Utils.AboutApp.about_app import about_app
from scytaledroid.DeviceAnalysis.device_analysis_menu import device_menu
from scytaledroid.Reporting.menu import reporting_menu
from scytaledroid.StaticAnalysis.menu import static_analysis_menu
from scytaledroid.DynamicAnalysis.menu import dynamic_analysis_menu
from scytaledroid.VirusTotal.menu import virustotal_menu
from scytaledroid.Utils.System.utils_menu import utils_menu
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def print_banner() -> None:
    """Display welcome banner with app metadata and local time in Minneapolis."""

    now_ct = datetime.now(zoneinfo.ZoneInfo("America/Chicago"))
    timestamp = now_ct.strftime("%Y-%m-%d %H:%M:%S %Z")

    menu_utils.print_banner(
        app_config.APP_NAME,
        app_config.APP_VERSION,
        app_config.APP_RELEASE,
        app_config.APP_DESCRIPTION,
    )
    menu_utils.print_metrics(
        [
            ("Local time (Minneapolis)", timestamp),
        ]
    )
    print()

    log.info(
        f"Application started - {app_config.APP_NAME} {app_config.APP_VERSION} ({app_config.APP_RELEASE}), "
        f"Local time: {timestamp}",
        category="application",
    )


def main_menu() -> None:
    """Render the main menu loop using the shared menu framework."""
    while True:
        menu_utils.print_header("Main Menu")
        options = {
            "1": "Connect to Android Device",
            "2": "VirusTotal analysis",
            "3": "Static analysis",
            "4": "Dynamic analysis",
            "5": "Reporting",
            "6": "Utils",
            "7": "About App",
        }
        menu_utils.print_menu(options, is_main=True)
        choice = prompt_utils.get_choice(valid=list(options.keys()) + ["0"])

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
            log.info("User selected: Utils", category="application")
            handle_utils()
        elif choice == "7":
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


def handle_utils() -> None:
    utils_menu()


def handle_about() -> None:
    about_app()


if __name__ == "__main__":
    print_banner()
    main_menu()
