from __future__ import annotations

from scytaledroid.DeviceAnalysis.inventory import progress as inventory_progress
from scytaledroid.Utils.DisplayUtils import colors, error_panels, severity, summary_cards, table_utils


def test_error_panel_divider_is_rendered_line() -> None:
    panel = error_panels.format_panel("Error", "Something happened", width=40, tone="error")
    lines = colors.strip(panel).splitlines()
    assert lines
    assert lines[0] == ("-" * 40 or "─" * 40)


def test_severity_delta_token_uses_valid_palette_styles() -> None:
    token = severity.format_delta_token("new", 3)
    assert "NEW:3" in colors.strip(token)


def test_inventory_progress_no_ansi_in_non_tty(capsys) -> None:
    printer = inventory_progress.make_cli_progress_printer()
    printer({"phase": "start", "phase_label": "Collecting packages"})
    printer(
        {
            "phase": "progress",
            "processed": 5,
            "total": 10,
            "elapsed_seconds": 12.0,
            "split_processed": 1,
        }
    )
    out = capsys.readouterr().out
    assert "\033[" not in out


def test_table_utils_unknown_column_style_does_not_raise(capsys) -> None:
    table_utils.render_table(
        ["Name", "Value"],
        [["alpha", 1]],
        column_styles=["nonexistent_style", "progress"],
    )
    out = colors.strip(capsys.readouterr().out)
    assert "alpha" in out


def test_summary_card_unknown_style_falls_back(capsys) -> None:
    rendered = summary_cards.format_summary_card(
        "Test",
        [summary_cards.summary_item("Key", "Value", value_style="nonexistent_style")],
    )
    assert "Value" in colors.strip(rendered)
