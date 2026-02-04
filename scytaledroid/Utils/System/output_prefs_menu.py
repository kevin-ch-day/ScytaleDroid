"""Interactive menu to configure output preferences."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuSpec

from . import output_prefs as prefs


def output_prefs_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Output Preferences")
        current = prefs.get()
        menu_utils.print_section("Current settings")
        print(f"  Verbose:           {'on' if current.verbose else 'off'}")
        print(f"  Analytics detail:  {'on' if current.analytics_detail else 'off'}")
        print(f"  String samples:    {current.string_max_samples}")
        print(f"  Endpoints panel:   cleartext-only={'on' if current.cleartext_only else 'off'}")

        options = [
            ("1", "Toggle verbose mode", None),
            ("2", "Toggle analytics ID detail", None),
            ("3", "Set max string samples", None),
            ("4", "Toggle cleartext-only endpoints", None),
        ]
        spec = MenuSpec(items=options, show_exit=True)
        menu_utils.render_menu(spec)
        choice = prompt_utils.get_choice([opt[0] for opt in options] + ["0"], default="0")
        if choice == "0":
            break
        if choice == "1":
            value = prefs.toggle_verbose()
            print(status_messages.status(f"Verbose is now {'on' if value else 'off'}", level="info"))
        elif choice == "2":
            value = prefs.toggle_analytics_detail()
            print(status_messages.status(f"Analytics detail is now {'on' if value else 'off'}", level="info"))
        elif choice == "3":
            response = prompt_utils.prompt_text("Max string samples", default=str(current.string_max_samples))
            new_val = prefs.set_string_max_samples(int(response) if response.isdigit() else current.string_max_samples)
            print(status_messages.status(f"String samples set to {new_val}", level="info"))
        elif choice == "4":
            value = prefs.toggle_cleartext_only()
            print(status_messages.status(f"Endpoints panel cleartext-only is now {'on' if value else 'off'}", level="info"))
