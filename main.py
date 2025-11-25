"""main.py - Entry point for ScytaleDroid CLI."""

from __future__ import annotations

from collections.abc import Callable
import argparse
import sys

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuSpec
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.System.world_clock.display import (
    ClockSnapshot,
    describe_timezone,
    format_display_time,
    format_dst_status_text,
    snapshot_clocks,
)
from scytaledroid.Utils.System.world_clock.state import ClockReference, WorldClockState, load_state


def _resolve_timezones() -> WorldClockState:
    return load_state()


def _describe_snapshot(snapshot: ClockSnapshot) -> tuple[str, str]:
    timestamp = format_display_time(snapshot.local_time)
    tz_label = describe_timezone(snapshot.timezone, snapshot.local_time)
    dst_text = format_dst_status_text(snapshot.dst_status, None, None)
    details = f"{timestamp} {tz_label} ({dst_text})"
    return snapshot.label, details


def _build_metrics(state: WorldClockState) -> list[tuple[str, str]]:
    try:
        snapshots = snapshot_clocks(
            state.clocks,
            primary=state.primary,
            category="configured",
            reference=state.reference,
        )
    except Exception as exc:  # pragma: no cover - defensive logging
        log.warning(
            f"Failed to load world clock snapshots: {exc}",
            category="application",
        )
        return []

    metrics: list[tuple[str, str]] = []
    for snapshot in snapshots:
        try:
            metrics.append(_describe_snapshot(snapshot))
        except Exception as exc:  # pragma: no cover - defensive logging
            log.warning(
                f"Failed to format clock metric for {snapshot.label}: {exc}",
                category="application",
            )
    return metrics


def print_banner(*, show_clocks: bool = False) -> None:
    """Display welcome banner with app metadata and optional world clock."""

    metrics: list[tuple[str, str]] = []
    if show_clocks:
        state = _resolve_timezones()
        metrics = _build_metrics(state)

    menu_utils.print_main_banner(
        app_config.APP_NAME,
        app_config.APP_VERSION,
        app_config.APP_RELEASE,
        app_config.APP_DESCRIPTION,
        metrics=metrics,
    )

    log.info(
        f"Application started - {app_config.APP_NAME} {app_config.APP_VERSION} ({app_config.APP_RELEASE})",
        category="application",
    )


def main_menu() -> None:
    """Render the main menu loop using the shared menu framework."""

    menu_actions: list[tuple[str, str, Callable[[], None]]] = [
        ("1", "Android devices", handle_device),
        ("2", "Static analysis", handle_static),
        ("3", "Harvest Android Permissions", handle_perm_catalog),
        ("4", "Dynamic analysis", handle_dynamic),
        ("5", "Reporting", handle_reporting),
        ("6", "Database utilities", handle_database),
        ("7", "Workspace maintenance & cleanup", handle_workspace),
        ("8", "APK library & archives", handle_browse_apks),
        ("9", "About App", handle_about),
    ]

    handlers = {key: (label, callback) for key, label, callback in menu_actions}
    valid_choices = list(handlers)
    default_choice = "1"
    while True:
        print()
        menu_utils.print_header("Main Menu")
        spec = MenuSpec(
            items=[menu_utils.MenuOption(key, label) for key, label, _ in menu_actions],
            default=default_choice,
            exit_label="Exit",
            show_exit=True,
            show_descriptions=False,
        )
        menu_utils.render_menu(spec)

        choice = prompt_utils.get_choice(
            valid=valid_choices + ["0"],
            default=default_choice,
        )

        if choice == "0":
            log.info("Application shutting down", category="application")
            status_messages.print_status("Goodbye!", level="info")
            break

        selected = handlers.get(choice)
        if not selected:
            log.warning(f"Invalid menu choice: {choice}", category="application")
            status_messages.print_status("Invalid choice. Please try again.", level="warn")
            continue

        label, callback = selected
        log.info(f"User selected: {label}", category="application")
        callback()


# --- Handlers for each menu option ---

def handle_device() -> None:
    """Launch the Android Devices hub."""
    from scytaledroid.DeviceAnalysis.device_hub_menu import devices_hub

    devices_hub()


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
        log.error(
            f"Failed to open permission catalog: {exc}",
            category="application",
        )
        status_messages.print_status(
            "Unable to open permission catalog. Check logs for details.",
            level="error",
        )


def handle_reporting() -> None:
    from scytaledroid.Reporting.menu import reporting_menu

    reporting_menu()


def handle_database() -> None:
    from scytaledroid.Database.db_utils.database_menu import database_menu

    database_menu()

def handle_utils() -> None:
    from scytaledroid.Utils.System.utils_menu import utils_menu

    utils_menu()


def handle_workspace() -> None:
    from scytaledroid.Utils.System.workspace_maintenance_menu import workspace_menu

    workspace_menu()


def handle_browse_apks() -> None:
    """Jump straight to the APK library browser."""
    try:
        from scytaledroid.DeviceAnalysis.apk_library_menu import apk_library_menu

        apk_library_menu()
    except Exception as exc:
        log.error(f"Failed to open APK library: {exc}", category="application")
        status_messages.print_status(
            "Unable to open APK library. Check logs for details.",
            level="error",
        )


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
        print()
        status_messages.print_status("Interrupted by user. Exiting…", level="warn")
        log.info("Application interrupted by user.", category="application")
    return 0


if __name__ == "__main__":
    sys.exit(main())
