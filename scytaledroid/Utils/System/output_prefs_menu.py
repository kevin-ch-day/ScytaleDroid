"""Interactive menu to configure output preferences."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import colors, menu_utils, prompt_utils, status_messages, ui_prefs
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuSpec
from scytaledroid.Utils.DisplayUtils.theme_preview import print_theme_preview

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
        print(f"  Color output:      {'on' if ui_prefs.use_color() else 'off'}")
        print(f"  Unicode symbols:   {'on' if ui_prefs.use_unicode() else 'off'}")
        print(f"  Theme:             {ui_prefs.get_theme()}")

        options = [
            ("1", "Toggle verbose mode", None),
            ("2", "Toggle analytics ID detail", None),
            ("3", "Set max string samples", None),
            ("4", "Toggle cleartext-only endpoints", None),
            ("5", "Toggle color output", None),
            ("6", "Toggle unicode symbols", None),
            ("7", "Choose color theme", None),
            ("8", "Preview current theme", None),
        ]
        spec = MenuSpec(items=options, show_exit=True)
        menu_utils.render_menu(spec)
        choice = prompt_utils.get_choice(
            menu_utils.selectable_keys(options, include_exit=True),
            default="0",
        )
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
        elif choice == "5":
            enabled = not ui_prefs.use_color()
            ui_prefs.set_use_color(enabled)
            print(status_messages.status(f"Color output is now {'on' if enabled else 'off'}", level="info"))
        elif choice == "6":
            enabled = not ui_prefs.use_unicode()
            ui_prefs.set_use_unicode(enabled)
            print(status_messages.status(f"Unicode symbols are now {'on' if enabled else 'off'}", level="info"))
        elif choice == "7":
            _select_theme()
        elif choice == "8":
            print()
            print_theme_preview(title="Current CLI Theme")


def _select_theme() -> None:
    current_theme = ui_prefs.get_theme()
    palette_names = colors.available_palettes()
    options = [(str(index + 1), name, None) for index, name in enumerate(palette_names)]
    options.append(("A", "Auto (environment-driven)", None))

    print()
    menu_utils.print_header("Choose Theme")
    print(status_messages.status(f"Current theme: {current_theme}", level="info"))
    menu_utils.render_menu(MenuSpec(items=options, show_exit=True))

    choice = prompt_utils.get_choice(
        menu_utils.selectable_keys(options, include_exit=True),
        default="0",
        casefold=True,
    )
    if choice == "0":
        return
    if choice.upper() == "A":
        selected = ui_prefs.reset_theme_auto()
        print(status_messages.status(f"Theme set to auto ({selected})", level="success"))
        return

    index = int(choice) - 1
    if index < 0 or index >= len(palette_names):
        print(status_messages.status("Invalid theme selection.", level="warn"))
        return

    selected = ui_prefs.set_theme(palette_names[index])
    print(status_messages.status(f"Theme set to {selected}", level="success"))
    print_theme_preview(title="Selected Theme")
