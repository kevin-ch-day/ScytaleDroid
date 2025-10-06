"""world_clock_configurator.py - Interactive world clock management flow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Optional

import zoneinfo

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .world_clock_display import render_clock_overview


@dataclass
class ClockState:
    """Current configuration snapshot for the world clock workflow."""

    clocks: Dict[str, str]
    defaults: Dict[str, str]
    max_clocks: int
    primary: Optional[str]
    local_label: Optional[str]
    local_timezone: Optional[str]


def configure_world_clocks() -> None:
    """Entry point for the interactive world clock configuration loop."""

    while True:
        state = _load_state()

        render_clock_overview(
            state.clocks,
            primary=state.primary,
            local_label=state.local_label,
            local_timezone=state.local_timezone,
            max_clocks=state.max_clocks,
        )

        menu = _build_menu(state)
        menu_utils.print_menu(menu, boxed=False)
        choice = prompt_utils.get_choice(["1", "2", "3", "4", "5", "6", "0"])

        if choice == "0":
            break

        handler = _ACTION_HANDLERS.get(choice)
        if handler:
            handler(state)
        else:
            print(status_messages.status("Action not available.", level="warn"))

        print()


def _load_state() -> ClockState:
    clocks = dict(getattr(app_config, "UI_TIMEZONES", {}))
    defaults = dict(getattr(app_config, "DEFAULT_UI_TIMEZONES", {}))
    configured_max = int(getattr(app_config, "UI_MAX_CLOCKS", 3))
    max_clocks = max(1, min(configured_max, 3))

    if len(clocks) > max_clocks:
        trimmed = list(clocks.items())[:max_clocks]
        clocks = dict(trimmed)
        app_config.UI_TIMEZONES = dict(trimmed)

    primary = getattr(app_config, "UI_PRIMARY_CLOCK", next(iter(clocks), None))
    if primary not in clocks:
        primary = next(iter(clocks), None)
        app_config.UI_PRIMARY_CLOCK = primary

    local_label = getattr(app_config, "UI_LOCAL_TIME_LABEL", primary)
    local_timezone = getattr(app_config, "UI_LOCAL_TIMEZONE", None)

    if local_label and local_label in clocks:
        local_timezone = clocks.get(local_label)
    if not local_timezone:
        local_timezone = clocks.get(primary) or "Etc/UTC"
        app_config.UI_LOCAL_TIMEZONE = local_timezone

    app_config.UI_LOCAL_TIME_LABEL = local_label or primary
    local_label = app_config.UI_LOCAL_TIME_LABEL

    return ClockState(
        clocks=clocks,
        defaults=defaults,
        max_clocks=max_clocks,
        primary=primary,
        local_label=local_label,
        local_timezone=local_timezone,
    )


def _build_menu(state: ClockState) -> list[menu_utils.MenuOption]:
    subtitle = f"Currently {state.local_label} — {state.local_timezone}" if state.local_label else None

    options = [
        menu_utils.MenuOption(
            "1",
            "Add or update clock",
            f"Store up to {state.max_clocks} cities",
        ),
        menu_utils.MenuOption(
            "2",
            "Remove clock",
            "Keep at least one clock",
        ),
        menu_utils.MenuOption(
            "3",
            "Reset to defaults",
            "Restore Minneapolis, Las Vegas, and Dubai",
        ),
        menu_utils.MenuOption(
            "4",
            "Set primary clock",
            "Controls highlighted ordering",
        ),
        menu_utils.MenuOption(
            "5",
            "Set local reference clock",
            subtitle,
        ),
        menu_utils.MenuOption(
            "6",
            "Refresh snapshot",
            "Update the table with the current times",
            hint="Helpful when leaving the menu open",
        ),
    ]
    return options


def _handle_add_or_update(state: ClockState) -> None:
    label = prompt_utils.prompt_text(
        "Clock label",
        default="City, Country",
        hint="Example: Tokyo, Japan",
    )
    cleaned_label = label.strip()
    if not cleaned_label:
        print(status_messages.status("Clock label cannot be blank.", level="warn"))
        return

    existing = cleaned_label in state.clocks
    if not existing and len(state.clocks) >= state.max_clocks:
        print(
            status_messages.status(
                f"Limit of {state.max_clocks} clocks reached. Remove one before adding a new city.",
                level="warn",
            )
        )
        return

    menu_utils.print_hint("Use a tz database name such as Europe/Paris or Etc/UTC.")
    existing_timezone = state.clocks.get(cleaned_label)
    tz_name = prompt_utils.prompt_text(
        "IANA timezone",
        default=existing_timezone,
        required=True,
    )
    try:
        zoneinfo.ZoneInfo(tz_name)
    except Exception:
        print(
            status_messages.status(
                "Invalid timezone identifier. Refer to the IANA tz database list.",
                level="error",
            )
        )
        return

    app_config.UI_TIMEZONES[cleaned_label] = tz_name
    if not app_config.UI_PRIMARY_CLOCK:
        app_config.UI_PRIMARY_CLOCK = cleaned_label
    print(status_messages.status(f"Clock for {cleaned_label} set to {tz_name}.", level="success"))


def _handle_remove(state: ClockState) -> None:
    if len(state.clocks) <= 1:
        print(status_messages.status("At least one clock must remain configured.", level="warn"))
        return

    label = prompt_utils.prompt_text(
        "Clock label to remove",
        default=next(iter(state.clocks.keys())),
        required=True,
    )
    cleaned_label = label.strip()
    if cleaned_label in app_config.UI_TIMEZONES:
        del app_config.UI_TIMEZONES[cleaned_label]
        if getattr(app_config, "UI_PRIMARY_CLOCK", None) == cleaned_label:
            app_config.UI_PRIMARY_CLOCK = next(iter(app_config.UI_TIMEZONES), None)
        print(status_messages.status(f"Removed clock '{cleaned_label}'.", level="success"))
    else:
        print(status_messages.status(f"No clock named '{cleaned_label}'.", level="warn"))


def _handle_reset(state: ClockState) -> None:
    if not prompt_utils.prompt_yes_no("Reset clocks to defaults?", default=False):
        return

    restored = {
        label: tz
        for label, tz in list(state.defaults.items())[: state.max_clocks]
    }
    app_config.UI_TIMEZONES = restored
    app_config.UI_PRIMARY_CLOCK = next(iter(restored), None)
    print(status_messages.status("World clocks reset to defaults.", level="success"))


def _handle_set_primary(state: ClockState) -> None:
    if not state.clocks:
        print(status_messages.status("No clocks configured yet.", level="warn"))
        return

    label = prompt_utils.prompt_text(
        "Primary display clock",
        default=state.primary or next(iter(state.clocks)),
        hint="Choose from the configured labels",
    )
    cleaned_label = label.strip()
    if cleaned_label in app_config.UI_TIMEZONES:
        app_config.UI_PRIMARY_CLOCK = cleaned_label
        print(status_messages.status(f"Primary clock set to {cleaned_label}.", level="success"))
    else:
        print(status_messages.status(f"No clock named '{cleaned_label}'.", level="warn"))


def _handle_set_local_reference(state: ClockState) -> None:
    suggested_label = state.local_label or state.primary or next(iter(state.clocks), "Local Reference")
    label = prompt_utils.prompt_text(
        "Local reference label",
        default=suggested_label,
        hint="Used in reports and summaries",
    )
    cleaned_label = label.strip() or suggested_label

    default_timezone = (
        state.clocks.get(cleaned_label)
        or state.local_timezone
        or state.clocks.get(state.primary)
        or "Etc/UTC"
    )
    menu_utils.print_hint("Enter an IANA timezone such as America/Chicago or Europe/Paris.")
    tz_name = prompt_utils.prompt_text(
        "Local reference timezone",
        default=default_timezone,
        required=True,
    )
    try:
        zoneinfo.ZoneInfo(tz_name)
    except Exception:
        print(
            status_messages.status(
                "Invalid timezone identifier provided for the local reference.",
                level="error",
            )
        )
        return

    app_config.UI_LOCAL_TIME_LABEL = cleaned_label
    app_config.UI_LOCAL_TIMEZONE = tz_name
    print(status_messages.status(f"Local reference set to {cleaned_label} ({tz_name}).", level="success"))


def _handle_refresh(_: ClockState) -> None:
    print(status_messages.status("Refreshing clock snapshot...", level="info"))


_ACTION_HANDLERS: Dict[str, Callable[[ClockState], None]] = {
    "1": _handle_add_or_update,
    "2": _handle_remove,
    "3": _handle_reset,
    "4": _handle_set_primary,
    "5": _handle_set_local_reference,
    "6": _handle_refresh,
}


__all__ = ["configure_world_clocks"]
