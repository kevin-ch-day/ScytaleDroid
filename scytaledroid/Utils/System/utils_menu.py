"""utils_menu.py - Utility menu dispatcher for the ScytaleDroid CLI."""

from __future__ import annotations

from typing import Callable, Dict

from scytaledroid.Utils.DisplayUtils import (
    menu_utils,
    prompt_utils,
    status_messages,
)

from . import util_actions
from .world_clock.configurator import configure_world_clocks


def utils_menu() -> None:
    """Render the utilities submenu and dispatch the selected action."""

    actions: Dict[str, Callable[[], None]] = {
        "1": util_actions.clear_screen,
        "2": util_actions.show_log_locations,
        "3": configure_world_clocks,
    }
    options = [
        menu_utils.MenuOption("1", "Clear the console", "Wipe the terminal output"),
        menu_utils.MenuOption("2", "Show log directories", "Quick reminders on where logs live"),
        menu_utils.MenuOption(
            "3",
            "Configure world clocks",
            "Manage the demo banner clocks",
        ),
    ]

    while True:
        print()
        menu_utils.print_header("Utilities")
        menu_utils.print_menu(options, is_main=False, boxed=False)

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
