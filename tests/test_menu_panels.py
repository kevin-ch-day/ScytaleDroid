from scytaledroid.Utils.DisplayUtils import colors, menu_utils


def test_format_menu_panel_renders_basic(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    colors.colors_enabled(force_refresh=True)
    monkeypatch.setattr(menu_utils, "get_terminal_width", lambda: 80)

    panel = menu_utils.format_menu_panel(
        "Sample Section",
        [
            menu_utils.MenuOption("1", "First Option", "Does the first thing"),
            menu_utils.MenuOption("2", "Second Option", "Handles the second task", hint="Requires setup"),
        ],
        width=48,
        default_keys=("1",),
    )

    plain = colors.strip(panel)
    assert "Sample Section" in plain
    assert "1)" in plain and "First Option" in plain
    assert "Second Option" in plain
    assert "Requires setup" in plain


def test_print_menu_panels_emits_expected_layout(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    colors.colors_enabled(force_refresh=True)
    monkeypatch.setattr(menu_utils, "get_terminal_width", lambda: 90)

    sections = [
        (
            "Group A",
            [
                menu_utils.MenuOption("1", "Alpha", "Primary workflow"),
                menu_utils.MenuOption("2", "Beta", "Secondary workflow"),
            ],
        ),
        (
            "Group B",
            [
                menu_utils.MenuOption("3", "Gamma", "Reporting suite"),
            ],
        ),
    ]

    menu_utils.print_menu_panels(sections, columns=2, default_keys=("1",))
    output = colors.strip(capsys.readouterr().out)

    assert "Group A" in output and "Group B" in output
    assert "1)" in output and "Alpha" in output
    assert "Gamma" in output
