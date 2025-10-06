"""Utility menu actions for the ScytaleDroid CLI."""

from __future__ import annotations

import os
import zoneinfo
from typing import Callable, Dict, Optional

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import (
    menu_utils,
    prompt_utils,
    status_messages,
)

from .world_clock_display import print_featured_snapshots, render_clock_overview


def utils_menu() -> None:
    """Render the utilities submenu and dispatch the selected action."""

    actions: Dict[str, Callable[[], None]] = {
        "1": clear_screen,
        "2": show_log_locations,
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

        # The world clock configurator already provides its own interaction loop.
        if choice != "3":
            prompt_utils.press_enter_to_continue()


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")
    print(status_messages.status("Screen cleared.", level="info"))


def show_log_locations() -> None:
    print(status_messages.status("Application logs: ./logs/application.log", level="info"))
    print(status_messages.status("Device analysis logs: ./logs/device_analysis.log", level="info"))
    print(status_messages.status("Command history / state: ./data/state/", level="info"))


def configure_world_clocks() -> None:
    """Interactive editor for the world clock banner configuration."""

    while True:
        current = dict(getattr(app_config, "UI_TIMEZONES", {}))
        defaults = getattr(app_config, "DEFAULT_UI_TIMEZONES", {})
        configured_max = int(getattr(app_config, "UI_MAX_CLOCKS", 3))
        max_clocks = max(1, min(configured_max, 3))
        primary = getattr(app_config, "UI_PRIMARY_CLOCK", next(iter(current), None))
        local_label = getattr(app_config, "UI_LOCAL_TIME_LABEL", primary)
        local_timezone = getattr(app_config, "UI_LOCAL_TIMEZONE", None)

        if local_label and local_label in current:
            local_timezone = current.get(local_label)
        if not local_timezone:
            local_timezone = current.get(primary) or "Etc/UTC"
            app_config.UI_LOCAL_TIMEZONE = local_timezone

        app_config.UI_LOCAL_TIME_LABEL = local_label or primary
        local_label = app_config.UI_LOCAL_TIME_LABEL

        if len(current) > max_clocks:
            trimmed_items = list(current.items())[:max_clocks]
            current = dict(trimmed_items)
            app_config.UI_TIMEZONES = dict(trimmed_items)
            if primary not in app_config.UI_TIMEZONES:
                app_config.UI_PRIMARY_CLOCK = next(iter(app_config.UI_TIMEZONES), None)
                primary = app_config.UI_PRIMARY_CLOCK

        render_clock_overview(
            current,
            primary=primary,
            local_label=local_label,
            local_timezone=local_timezone,
            max_clocks=max_clocks,
        )

        menu = [
            menu_utils.MenuOption(
                "1",
                "Add or update clock",
                f"Store up to {max_clocks} cities",
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
                "Controls the highlighted display order",
            ),
            menu_utils.MenuOption(
                "5",
                "Set local reference clock",
                f"Currently {local_label} — {local_timezone}",
            ),
            menu_utils.MenuOption(
                "6",
                "View featured cities",
                "Paris and London snapshots (UTC alignment)",
            ),
            menu_utils.MenuOption(
                "7",
                "Refresh snapshot",
                "Update the table with the current times",
                hint="Useful when leaving the menu open during demos",
            ),
        ]
        menu_utils.print_menu(menu, boxed=False)
        choice = prompt_utils.get_choice(["1", "2", "3", "4", "5", "6", "7", "0"])

        if choice == "0":
            break

        if choice == "1":
            label = prompt_utils.prompt_text(
                "Clock label",
                default="City, Country",
                hint="Example: Tokyo, Japan",
            )
            cleaned_label = label.strip()
            if not cleaned_label:
                print(status_messages.status("Clock label cannot be blank.", level="warn"))
                continue

            existing = cleaned_label in current
            if not existing and len(current) >= max_clocks:
                print(
                    status_messages.status(
                        f"Limit of {max_clocks} clocks reached. Remove one before adding a new city.",
                        level="warn",
                    )
                )
                continue

            menu_utils.print_hint(
                "Use an official tz database name such as Europe/Paris or Etc/UTC.",
            )
            existing_timezone = current.get(cleaned_label)
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
                        "Invalid timezone identifier. Refer to https://en.wikipedia.org/wiki/List_of_tz_database_time_zones.",
                        level="error",
                    )
                )
                continue

            app_config.UI_TIMEZONES[cleaned_label] = tz_name
            if not app_config.UI_PRIMARY_CLOCK:
                app_config.UI_PRIMARY_CLOCK = cleaned_label
            print(
                status_messages.status(
                    f"Clock for {cleaned_label} set to {tz_name}.",
                    level="success",
                )
            )

        elif choice == "2":
            if len(current) <= 1:
                print(
                    status_messages.status(
                        "At least one clock must remain configured.",
                        level="warn",
                    )
                )
                continue

            label = prompt_utils.prompt_text(
                "Clock label to remove",
                default=next(iter(current.keys())),
            )
            cleaned_label = label.strip()
            if cleaned_label in app_config.UI_TIMEZONES:
                del app_config.UI_TIMEZONES[cleaned_label]
                if getattr(app_config, "UI_PRIMARY_CLOCK", None) == cleaned_label:
                    app_config.UI_PRIMARY_CLOCK = next(iter(app_config.UI_TIMEZONES), None)
                print(
                    status_messages.status(
                        f"Removed clock '{cleaned_label}'.",
                        level="success",
                    )
                )
            else:
                print(status_messages.status(f"No clock named '{cleaned_label}'.", level="warn"))

        elif choice == "3":
            if prompt_utils.prompt_yes_no("Reset clocks to defaults?", default=False):
                app_config.UI_TIMEZONES = {
                    label: tz
                    for label, tz in list(defaults.items())[:max_clocks]
                }
                app_config.UI_PRIMARY_CLOCK = next(iter(app_config.UI_TIMEZONES), None)
                print(status_messages.status("World clocks reset to defaults.", level="success"))

        elif choice == "4":
            if not current:
                print(status_messages.status("No clocks configured yet.", level="warn"))
                continue

            label = prompt_utils.prompt_text(
                "Primary display clock",
                default=primary or next(iter(current)),
                hint="Choose from the configured labels",
            )
            cleaned_label = label.strip()
            if cleaned_label in app_config.UI_TIMEZONES:
                app_config.UI_PRIMARY_CLOCK = cleaned_label
                print(
                    status_messages.status(
                        f"Primary clock set to {cleaned_label}.",
                        level="success",
                    )
                )
            else:
                print(status_messages.status(f"No clock named '{cleaned_label}'.", level="warn"))

        elif choice == "5":
            suggested_label = local_label or primary or next(iter(current), "Local Reference")
            label = prompt_utils.prompt_text(
                "Local reference label",
                default=suggested_label,
                hint="Used in reports and summaries",
            )
            cleaned_label = label.strip() or suggested_label

            default_timezone = (
                current.get(cleaned_label)
                or local_timezone
                or current.get(primary)
                or "Etc/UTC"
            )
            menu_utils.print_hint(
                "Enter an IANA timezone such as America/Chicago, Europe/Paris, or Etc/UTC.",
            )
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
                continue

            app_config.UI_LOCAL_TIME_LABEL = cleaned_label
            app_config.UI_LOCAL_TIMEZONE = tz_name
            print(
                status_messages.status(
                    f"Local reference set to {cleaned_label} ({tz_name}).",
                    level="success",
                )
            )

        elif choice == "6":
            print_featured_snapshots()

        elif choice == "7":
            # Loop iteration will re-render the table with up-to-date times.
            print(status_messages.status("Refreshing clock snapshot...", level="info"))

        print()
