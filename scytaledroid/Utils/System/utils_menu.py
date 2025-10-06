"""Utility menu actions for Scytaledroid CLI."""

from __future__ import annotations

import os
from datetime import datetime
import zoneinfo
from typing import Callable, Dict

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Config import app_config


def utils_menu() -> None:
    actions: Dict[str, Callable[[], None]] = {
        "1": clear_screen,
        "2": show_log_locations,
        "3": configure_world_clocks,
    }
    options = [
        menu_utils.MenuOption("1", "Clear the console", "Wipe the terminal output"),
        menu_utils.MenuOption("2", "Show log directories", "Quick reminders on where logs live"),
        menu_utils.MenuOption("3", "Configure world clocks", "Add, remove, or reset banner clocks"),
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
        if action:
            action()
        else:
            print(status_messages.status("Action not available.", level="warn"))
        prompt_utils.press_enter_to_continue()


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")
    print(status_messages.status("Screen cleared.", level="info"))


def show_log_locations() -> None:
    print(status_messages.status("Application logs: ./logs/application.log", level="info"))
    print(status_messages.status("Device analysis logs: ./logs/device_analysis.log", level="info"))
    print(status_messages.status("Command history / state: ./data/state/", level="info"))


def configure_world_clocks() -> None:
    while True:
        current = dict(getattr(app_config, "UI_TIMEZONES", {}))
        defaults = getattr(app_config, "DEFAULT_UI_TIMEZONES", {})
        max_clocks = getattr(app_config, "UI_MAX_CLOCKS", 3)
        primary = getattr(app_config, "UI_PRIMARY_CLOCK", next(iter(current), None))

        _print_clock_table(current, primary)

        menu = [
            menu_utils.MenuOption("1", "Add or update clock", f"Store up to {max_clocks} cities"),
            menu_utils.MenuOption("2", "Remove clock", "Keep at least one clock"),
            menu_utils.MenuOption("3", "Reset to defaults", "Restore recommended cities"),
            menu_utils.MenuOption("4", "Set primary clock", "Controls display order"),
        ]
        menu_utils.print_menu(menu, boxed=False)
        choice = prompt_utils.get_choice(["1", "2", "3", "4", "0"])

        if choice == "0":
            break
        if choice == "1":
            label = prompt_utils.prompt_text(
                "Clock label",
                default="City, Country",
                hint="Example: Tokyo, Japan",
            )
            existing = label in current
            if not existing and len(current) >= max_clocks:
                print(status_messages.status(f"Limit of {max_clocks} clocks reached.", level="warn"))
                continue
            print(status_messages.status("Example timezone: Asia/Tokyo", level="info"))
            tz_name = prompt_utils.prompt_text(
                "IANA timezone",
                hint="Use tz database names (e.g., Europe/Paris)",
            )
            try:
                zoneinfo.ZoneInfo(tz_name)
            except Exception:
                print(status_messages.status("Invalid timezone identifier.", level="error"))
                continue
            app_config.UI_TIMEZONES[label] = tz_name
            print(status_messages.status(f"Clock for {label} set to {tz_name}.", level="success"))
        elif choice == "2":
            if not current:
                print(status_messages.status("No clocks to remove.", level="warn"))
                continue
            if len(current) <= 1:
                print(status_messages.status("At least one clock must remain.", level="warn"))
                continue
            label = prompt_utils.prompt_text(
                "Clock label to remove",
                default=next(iter(current.keys())),
            )
            if label in app_config.UI_TIMEZONES:
                del app_config.UI_TIMEZONES[label]
                if getattr(app_config, "UI_PRIMARY_CLOCK", None) == label:
                    app_config.UI_PRIMARY_CLOCK = next(iter(app_config.UI_TIMEZONES), None)
                print(status_messages.status(f"Removed clock '{label}'.", level="success"))
            else:
                print(status_messages.status(f"No clock named '{label}'.", level="warn"))
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
                "Primary clock label",
                default=primary or next(iter(current)),
                hint="Choose from the configured labels",
            )
            if label in app_config.UI_TIMEZONES:
                app_config.UI_PRIMARY_CLOCK = label
                print(status_messages.status(f"Primary clock set to {label}.", level="success"))
            else:
                print(status_messages.status(f"No clock named '{label}'.", level="warn"))
        print()


def _print_clock_table(clocks: Dict[str, str], primary: Optional[str]) -> None:
    if not clocks:
        print(status_messages.status("No world clocks configured.", level="warn"))
        return

    headers = ["★", "City", "Country", "Timezone", "UTC", "Local time"]
    rows = []
    for label, tz in clocks.items():
        city, country = (label.split(",", 1) + [""])[:2]
        city = city.strip()
        country = country.strip()
        try:
            zone = zoneinfo.ZoneInfo(tz)
            now = datetime.now(zone)
        except Exception:
            now = datetime.utcnow()
            zone = None
        marker = "★" if label == primary else ""
        offset = "UTC"
        if zone:
            delta = now.utcoffset()
            if delta is not None:
                total_minutes = int(delta.total_seconds() // 60)
                hours, minutes = divmod(abs(total_minutes), 60)
                sign = "+" if total_minutes >= 0 else "-"
                offset = f"UTC{sign}{hours:02d}:{minutes:02d}"
        rows.append(
            [
                marker,
                city or label,
                country or "—",
                tz,
                offset,
                now.strftime("%Y-%m-%d %H:%M:%S"),
            ]
        )

    table_utils.render_table(headers, rows)
    max_clocks = getattr(app_config, "UI_MAX_CLOCKS", 3)
    print(status_messages.status(f"Tracking {len(clocks)}/{max_clocks} clocks.", level="info"))
        print()



__all__ = ["utils_menu"]
