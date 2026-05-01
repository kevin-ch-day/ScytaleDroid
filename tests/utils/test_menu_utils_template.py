from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import colors, menu_utils


def test_selectable_keys_excludes_disabled_entries() -> None:
    items = [
        menu_utils.MenuOption("1", "Enabled"),
        menu_utils.MenuOption("2", "Disabled", disabled=True),
        menu_utils.MenuOption("3", "Also enabled"),
    ]
    keys = menu_utils.selectable_keys(items, include_exit=True)
    assert keys == ["1", "3", "0"]


def test_selectable_keys_avoids_duplicate_exit_and_duplicate_keys() -> None:
    items = [
        menu_utils.MenuOption("1", "First"),
        menu_utils.MenuOption("0", "Back alias"),
        menu_utils.MenuOption("1", "Duplicate"),
    ]
    keys = menu_utils.selectable_keys(items, include_exit=True)
    assert keys == ["1", "0"]


def test_render_menu_supports_template_metadata(capsys) -> None:
    spec = menu_utils.MenuSpec(
        items=[menu_utils.MenuOption("1", "Run check", "Runs the standard check set")],
        show_exit=True,
        title="Run Menu",
        subtitle="Choose action",
        hint="Use option 1 to execute checks",
        footer="Tip: press 0 to return",
    )
    menu_utils.render_menu(spec)
    out = colors.strip(capsys.readouterr().out)
    assert "Run Menu" in out
    assert "Choose action" in out
    assert "Use option 1 to execute checks" in out
    assert "Tip: press 0 to return" in out
