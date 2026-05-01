"""world_clock_configurator.py - Interactive world clock management flow."""

from __future__ import annotations

import zoneinfo
from collections.abc import Callable
from datetime import datetime

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .display import render_clock_overview, render_dst_schedule
from .log_alignment import derive_reference_from_log
from .state import (
    ClockLimitError,
    MinimumClockError,
    TimezoneValidationError,
    WorldClockState,
    load_state,
    remove_clock,
    set_primary_clock,
    set_reference_custom,
    set_reference_now,
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
            reference=state.reference,
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
            "Refresh snapshot or open reference tools",
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


def _handle_reference(state: WorldClockState) -> None:
    reference = state.reference
    if reference.mode == "custom" and reference.timezone:
        tz_display = reference.timezone
        status_localized = reference.utc.astimezone(zoneinfo.ZoneInfo(reference.timezone))
    else:
        tz_display = reference.timezone or "UTC"
        status_localized = reference.utc

    formatted = status_localized.strftime("%Y-%m-%d %H:%M")
    status = (
        f"Snapshot anchored to '{reference.label}' — {tz_display} @ {formatted}"
        if reference.mode == "custom"
        else "Snapshot uses live time."
    )
    print(status_messages.status(status, level="info"))

    options = [
        menu_utils.MenuOption("1", "Live system time", "Always show the current moment"),
        menu_utils.MenuOption("2", "Custom reference", "Manually set date and time"),
        menu_utils.MenuOption(
            "3",
            "Derive from log timestamp",
            "Preview alignment and optionally adopt the result",
        ),
    ]
    menu_utils.print_menu(options, boxed=False)
    choice = prompt_utils.get_choice(
        menu_utils.selectable_keys(options, include_exit=True),
        default="1",
        disabled=[opt.key for opt in options if opt.disabled],
    )

    if choice == "0":
        return
    if choice == "1":
        set_reference_now()
        print(status_messages.status("Reference reset to live time.", level="success"))
        return

    if choice == "3":
        derive_reference_from_log(state)
        return

    label = prompt_utils.prompt_text(
        "Reference label",
        default=reference.label if reference.mode == "custom" else "Log snapshot",
        hint="Example: Device log capture start",
    ).strip() or "Log snapshot"

    default_timezone = (
        reference.timezone
        or state.primary_timezone
        or next(iter(state.clocks.values()), "Etc/UTC")
    )
    tz_name = prompt_utils.prompt_text(
        "Reference timezone",
        default=default_timezone,
        required=True,
        hint="Use an IANA name such as America/Chicago",
    )

    def _validate_date(value: str) -> bool:
        try:
            datetime.strptime(value, "%Y-%m-%d")
            return True
        except ValueError:
            return False

    def _validate_time(value: str) -> bool:
        parts = value.split(":")
        if len(parts) not in (2, 3):
            return False
        try:
            hour = int(parts[0])
            minute = int(parts[1])
            second = int(parts[2]) if len(parts) == 3 else 0
        except ValueError:
            return False
        return 0 <= hour < 24 and 0 <= minute < 60 and 0 <= second < 60

    try:
        tz_for_defaults = zoneinfo.ZoneInfo(tz_name)
        defaults_localized = reference.utc.astimezone(tz_for_defaults)
    except Exception:
        defaults_localized = status_localized

    date_default = defaults_localized.strftime("%Y-%m-%d")
    time_default = defaults_localized.strftime("%H:%M")

    date_text = prompt_utils.prompt_text(
        "Date (YYYY-MM-DD)",
        default=date_default,
        validator=_validate_date,
        error_message="Date must be in YYYY-MM-DD format.",
    )
    time_text = prompt_utils.prompt_text(
        "Time (HH:MM[:SS])",
        default=time_default,
        validator=_validate_time,
        error_message="Time must be HH:MM or HH:MM:SS in 24-hour time.",
    )

    try:
        if len(time_text.split(":")) == 3:
            local_dt = datetime.strptime(
                f"{date_text} {time_text}", "%Y-%m-%d %H:%M:%S"
            )
        else:
            local_dt = datetime.strptime(
                f"{date_text} {time_text}", "%Y-%m-%d %H:%M"
            )
        set_reference_custom(label, tz_name, local_dt)
    except TimezoneValidationError as exc:
        print(status_messages.status(str(exc), level="error"))
        return
    except ValueError:
        print(
            status_messages.status(
                "Unable to parse the provided date/time values.",
                level="error",
            )
        )
        return

    print(
        status_messages.status(
            f"Reference frozen at {date_text} {time_text} ({tz_name}).",
            level="success",
        )
    )


def _handle_dst_schedule(state: WorldClockState) -> None:
    render_dst_schedule(
        state.clocks,
        primary=state.primary,
        reference=state.reference,
    )


def _handle_refresh_menu(state: WorldClockState) -> None:
    options = [
        menu_utils.MenuOption("1", "Refresh snapshot", "Update to the latest times"),
        menu_utils.MenuOption(
            "2",
            "Adjust reference time",
            "Align to live, custom, or log timestamps",
        ),
        menu_utils.MenuOption(
            "3",
            "View DST schedule",
            "Review daylight saving status for configured cities",
        ),
    ]

    menu_utils.print_menu(options, boxed=False)
    choice = prompt_utils.get_choice(
        menu_utils.selectable_keys(options, include_exit=True),
        default="1",
        disabled=[opt.key for opt in options if opt.disabled],
    )

    if choice == "0":
        return
    if choice == "1":
        _handle_refresh(state)
    elif choice == "2":
        _handle_reference(state)
    elif choice == "3":
        _handle_dst_schedule(state)


_ACTION_HANDLERS: dict[str, Callable[[WorldClockState], None]] = {
    "1": _handle_add_or_update,
    "2": _handle_remove,
    "3": _handle_set_primary,
    "4": _handle_refresh_menu,
}


__all__ = ["configure_world_clocks"]
