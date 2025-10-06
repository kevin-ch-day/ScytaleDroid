"""world_clock_configurator.py - Interactive world clock management flow."""

from __future__ import annotations

from typing import Callable, Dict

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .world_clock_display import render_clock_overview
from .world_clock_state import (
    ClockLimitError,
    MinimumClockError,
    TimezoneValidationError,
    WorldClockState,
    load_state,
    remove_clock,
    set_primary_clock,
    upsert_clock,
)


def configure_world_clocks() -> None:
    """Entry point for the interactive world clock configuration loop."""

    while True:
        state = load_state()

        render_clock_overview(
            state.clocks,
            primary=state.primary,
            primary_timezone=state.primary_timezone,
        )

        menu = _build_menu(state)
        menu_utils.print_menu(menu, boxed=False)
        valid_choices = [option.key for option in menu]
        disabled_choices = [option.key for option in menu if getattr(option, "disabled", False)]
        choice = prompt_utils.get_choice(
            valid_choices + ["0"],
            disabled=disabled_choices,
        )

        if choice == "0":
            break

        handler = _ACTION_HANDLERS.get(choice)
        if handler:
            handler(state)
        else:
            print(status_messages.status("Action not available.", level="warn"))

        print()


def _build_menu(state: WorldClockState) -> list[menu_utils.MenuOption]:
    configured_count = len(state.clocks)
    remove_disabled = configured_count <= 1
    add_disabled = configured_count >= state.max_clocks

    options = [
        menu_utils.MenuOption(
            "1",
            "Add or update clock",
            f"Manage up to {state.max_clocks} cities (currently {configured_count})",
            disabled=add_disabled,
            hint=(
                "At capacity — update an existing label instead"
                if add_disabled
                else "Reusing an existing label updates its timezone"
            ),
        ),
        menu_utils.MenuOption(
            "2",
            "Remove clock",
            "Keep at least one clock",
            disabled=remove_disabled,
            hint="Removal is disabled when only one clock remains" if remove_disabled else None,
        ),
        menu_utils.MenuOption(
            "3",
            "Set primary clock",
            "Controls highlighted ordering",
        ),
        menu_utils.MenuOption(
            "4",
            "Refresh time",
            "Update the table with the latest snapshot",
        ),
    ]
    return options


def _handle_add_or_update(state: WorldClockState) -> None:
    label = prompt_utils.prompt_text(
        "Clock label",
        default="City, Country",
        hint="Example: Tokyo, Japan",
    )
    cleaned_label = label.strip()
    if not cleaned_label:
        print(status_messages.status("Clock label cannot be blank.", level="warn"))
        return

    menu_utils.print_hint("Use a tz database name such as Europe/Paris or Etc/UTC.")
    existing_timezone = state.clocks.get(cleaned_label)
    tz_name = prompt_utils.prompt_text(
        "IANA timezone",
        default=existing_timezone,
        required=True,
    )
    try:
        existed = upsert_clock(cleaned_label, tz_name, max_clocks=state.max_clocks)
    except ClockLimitError as exc:
        print(status_messages.status(str(exc), level="warn"))
        return
    except TimezoneValidationError as exc:
        print(status_messages.status(str(exc), level="error"))
        return

    action = "Updated" if existed else "Added"
    print(
        status_messages.status(
            f"{action} clock '{cleaned_label}' ({tz_name}).",
            level="success",
        )
    )


def _handle_remove(state: WorldClockState) -> None:
    label = prompt_utils.prompt_text(
        "Clock label to remove",
        default=next(iter(state.clocks.keys())),
        required=True,
    )
    cleaned_label = label.strip()
    try:
        removed = remove_clock(cleaned_label, min_clocks=1)
    except MinimumClockError as exc:
        print(status_messages.status(str(exc), level="warn"))
        return

    if removed:
        print(status_messages.status(f"Removed clock '{cleaned_label}'.", level="success"))
    else:
        print(status_messages.status(f"No clock named '{cleaned_label}'.", level="warn"))


def _handle_set_primary(state: WorldClockState) -> None:
    if not state.clocks:
        print(status_messages.status("No clocks configured yet.", level="warn"))
        return

    label = prompt_utils.prompt_text(
        "Primary display clock",
        default=state.primary or next(iter(state.clocks)),
        hint="Choose from the configured labels",
    )
    cleaned_label = label.strip()
    try:
        set_primary_clock(cleaned_label)
    except KeyError:
        print(status_messages.status(f"No clock named '{cleaned_label}'.", level="warn"))
        return

    print(status_messages.status(f"Primary clock set to {cleaned_label}.", level="success"))


def _handle_refresh(_: WorldClockState) -> None:
    print(status_messages.status("Refreshing clock snapshot...", level="info"))


_ACTION_HANDLERS: Dict[str, Callable[[WorldClockState], None]] = {
    "1": _handle_add_or_update,
    "2": _handle_remove,
    "3": _handle_set_primary,
    "4": _handle_refresh,
}


__all__ = ["configure_world_clocks"]
