"""utils_menu.py - Utility menu dispatcher for the ScytaleDroid CLI."""

from __future__ import annotations

from collections.abc import Callable

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import (
    menu_utils,
    prompt_utils,
    status_messages,
)
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from . import util_actions
from .world_clock.configurator import configure_world_clocks


def utils_menu() -> None:
    """Render the utilities submenu and dispatch the selected action."""

    actions: dict[str, Callable[[], None]] = {
        "1": util_actions.clear_screen,
        "2": util_actions.show_log_locations,
        "3": configure_world_clocks,
        "4": _open_output_prefs_menu,
        "5": util_actions.clean_static_analysis_artifacts,
    }
    options = [
        MenuOption("1", "Clear the console", "Wipe the terminal output"),
        MenuOption("2", "Show log directories", "Quick reminders on where logs live"),
        MenuOption(
            "3",
            "Configure world clocks",
            "Manage the demo banner clocks",
        ),
        MenuOption(
            "4",
            "Output preferences",
            "Set verbosity, analytics detail, and sample limits",
        ),
        MenuOption(
            "5",
            "Housekeep static-analysis artefacts",
            (
                "Prune stale JSON/HTML reports ("
                f"{app_config.STATIC_ANALYSIS_RETENTION_DAYS}-day retention)"
                " and reset cache directories"
            ),
        ),
    ]

    while True:
        print()
        menu_utils.print_header("Utilities")
        spec = MenuSpec(
            items=options,
            show_exit=True,
            exit_label="Back",
        )
        menu_utils.render_menu(spec)

        valid_keys = [item.key for item in options]
        choice = prompt_utils.get_choice(valid_keys + ["0"])

        if choice == "0":
            break

        action = actions.get(choice)
        if not action:
            print(status_messages.status("Action not available.", level="warn"))
            continue

        action()

        # The world clock configurator manages its own loop.
        if choice != "3":
            prompt_utils.press_enter_to_continue()


def _open_output_prefs_menu() -> None:
    try:
        from .output_prefs_menu import output_prefs_menu

        output_prefs_menu()
    except Exception as exc:
        print(
            status_messages.status(
                f"Output preferences not available: {exc}", level="warn"
            )
        )
