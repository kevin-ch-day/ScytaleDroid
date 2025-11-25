"""Menu dispatcher for reporting workflows."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

from .menu_actions import (
    handle_device_report,
    handle_static_report,
    view_saved_reports,
)


def reporting_menu() -> None:
    """Render the reporting menu until the user chooses to exit."""

    actions = {
        "1": handle_device_report,
        "2": handle_static_report,
        "3": view_saved_reports,
    }

    options = [
        MenuOption(
            "1",
            "Generate device summary report",
            description="Use the active device or select another connected target",
        ),
        MenuOption(
            "2",
            "Generate static analysis report",
            description="Convert a stored static analysis JSON artefact to markdown",
        ),
        MenuOption(
            "3",
            "View saved reports",
            description="Browse previously generated markdown reports",
        ),
    ]

    while True:
        print()
        menu_utils.print_header("Reporting")
        spec = MenuSpec(items=options, default="1")
        menu_utils.render_menu(spec)
        choice = prompt_utils.get_choice([option.key for option in options] + ["0"], default="0")

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            action()
        else:  # pragma: no cover - defensive path
            print(status_messages.status("Option not implemented yet.", level="warn"))
            prompt_utils.press_enter_to_continue()


__all__ = ["reporting_menu"]
