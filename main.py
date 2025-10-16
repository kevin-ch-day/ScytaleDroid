"""main.py - Entry point for ScytaleDroid CLI."""

from __future__ import annotations

import argparse
import sys
from zoneinfo import ZoneInfo

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.System.world_clock.state import ClockReference, WorldClockState, load_state


def _resolve_timezones() -> WorldClockState:
    return load_state()


def _format_time(tz_name: str, reference: ClockReference) -> str:
    tz = ZoneInfo(tz_name)
    snapshot = reference.utc.astimezone(tz)
    time_part = snapshot.strftime("%I:%M %p").lstrip("0")
    date_part = f"{snapshot.month}-{snapshot.day}-{snapshot.year}"
    tz_label = snapshot.tzname() or tz_name
    dst_delta = tz.dst(snapshot)
    dst_active = bool(dst_delta and dst_delta.total_seconds())
    dst_label = "DST" if dst_active else "Std"
    return f"{date_part} {time_part} {tz_label} ({dst_label})"


def print_banner(*, show_clocks: bool = False) -> None:
    """Display welcome banner with app metadata and optional world clock."""

    menu_utils.print_banner(
        app_config.APP_NAME,
        app_config.APP_VERSION,
        app_config.APP_RELEASE,
        app_config.APP_DESCRIPTION,
    )

    if show_clocks:
        state = _resolve_timezones()
        tz_mapping = state.clocks
        metrics = []
        for label, tz_name in tz_mapping.items():
            try:
                metrics.append((label, _format_time(tz_name, state.reference)))
            except Exception as exc:
                log.warning(
                    f"Failed to render time for {label}: {exc}", category="application"
                )
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
        print()
        menu_utils.print_header("Main Menu")
        options = [
            menu_utils.MenuOption("1", "Connect to Android Device", "Manage connected devices, inventory, and pulls"),
            menu_utils.MenuOption("2", "VirusTotal analysis", "Look up hashes and APKs against VirusTotal"),
            menu_utils.MenuOption("3", "Static analysis", "Run static checks on harvested applications"),
            menu_utils.MenuOption("4", "Harvest Android Permissions", "Fetch from developer.android.com and manage JSON cache"),
            menu_utils.MenuOption("5", "Dynamic analysis", "Launch runtime instrumentation workflows"),
            menu_utils.MenuOption("6", "Reporting", "Generate device and artifact reports"),
            menu_utils.MenuOption("7", "Database Utilities", "Inspect schema, check connection, and view counts"),
            menu_utils.MenuOption("8", "Database Scripts & Tasks", "Curated scripts to maintain and analyze the database"),
            menu_utils.MenuOption("9", "Utilities", "Console helpers and configuration"),
            menu_utils.MenuOption("10", "About App", "Show version and licensing information"),
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
            log.info("User selected: Harvest Android Permissions", category="application")
            handle_perm_catalog()
        elif choice == "5":
            log.info("User selected: Dynamic analysis", category="application")
            handle_dynamic()
        elif choice == "6":
            log.info("User selected: Reporting", category="application")
            handle_reporting()
        elif choice == "7":
            log.info("User selected: Database Utilities", category="application")
            handle_database()
        elif choice == "8":
            log.info("User selected: Database Scripts & Tasks", category="application")
            handle_db_scripts()
        elif choice == "9":
            log.info("User selected: Utils", category="application")
            handle_utils()
        elif choice == "10":
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
    from scytaledroid.DeviceAnalysis.device_analysis_menu import device_menu

    device_menu()


def handle_virustotal() -> None:
    from scytaledroid.VirusTotal.menu import virustotal_menu

    virustotal_menu()


def handle_static() -> None:
    from scytaledroid.StaticAnalysis.cli import static_analysis_menu

    static_analysis_menu()


def handle_dynamic() -> None:
    from scytaledroid.DynamicAnalysis.menu import dynamic_analysis_menu

    dynamic_analysis_menu()

def handle_perm_catalog() -> None:
    # Open the Harvest Android Permissions menu directly
    try:
        from scytaledroid.Utils.AndroidPermCatalog.cli import perm_catalog_menu  # noqa: WPS433
        perm_catalog_menu()
    except Exception as exc:
        print(f"Failed to open permission catalog: {exc}")


def handle_reporting() -> None:
    from scytaledroid.Reporting.menu import reporting_menu

    reporting_menu()


def handle_database() -> None:
    from scytaledroid.Database.db_utils.menu import database_menu

    database_menu()

def handle_db_scripts() -> None:
    from scytaledroid.Database.db_utils.menus.db_scripts_menu import scripts_menu

    scripts_menu()


def handle_utils() -> None:
    from scytaledroid.Utils.System.utils_menu import utils_menu

    utils_menu()


def handle_about() -> None:
    from scytaledroid.Utils.AboutApp.about_app import about_app

    about_app()


def _run_diagnostics(json_mode: bool) -> None:
    from scytaledroid.Diagnostics.runner import run as run_diagnostics

    run_diagnostics(json_mode=json_mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ScytaleDroid CLI")
    parser.add_argument(
        "--diag",
        action="store_true",
        help="Run diagnostics checks and exit",
    )
    parser.add_argument(
        "--with-clocks",
        action="store_true",
        help="Show multi-city clocks in the banner",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit diagnostics in JSON format (requires --diag)",
    )
    args = parser.parse_args(argv)

    if args.json and not args.diag:
        parser.error("--json requires --diag")

    if args.diag:
        _run_diagnostics(json_mode=args.json)
        return 0

    print_banner(show_clocks=args.with_clocks)
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")
        log.info("Application interrupted by user.", category="application")
    return 0


if __name__ == "__main__":
    sys.exit(main())
