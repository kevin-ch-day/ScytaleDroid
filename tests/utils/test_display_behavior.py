from __future__ import annotations

from pathlib import Path

from scytaledroid.DeviceAnalysis.inventory import progress as inventory_progress
from scytaledroid.Utils.DisplayUtils import colors, error_panels, menu_utils, severity, summary_cards, table_utils


_ALLOWED_RAW_ANSI_FILES = {
    Path("scytaledroid/Utils/DisplayUtils/colors/ansi.py"),
    Path("scytaledroid/Utils/DisplayUtils/text_blocks.py"),
    Path("scytaledroid/DeviceAnalysis/inventory/progress.py"),
}


def test_raw_ansi_sequences_are_limited_to_allowlist() -> None:
    root = Path(__file__).resolve().parents[2]
    violations: list[str] = []
    for path in root.joinpath("scytaledroid").rglob("*.py"):
        rel = path.relative_to(root)
        content = path.read_text(encoding="utf-8")
        has_raw_ansi = "\\033[" in content or "\\x1b[" in content
        if has_raw_ansi and rel not in _ALLOWED_RAW_ANSI_FILES:
            violations.append(str(rel))
    assert violations == []


def test_print_table_accepts_row_dicts(capsys) -> None:
    table_utils.print_table(
        [
            {"A": "x", "B": 1},
            {"A": "y", "B": 2},
        ],
        headers=["A", "B"],
    )
    out = capsys.readouterr().out
    assert "A" in out
    assert "B" in out
    assert "x" in out


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


def test_inventory_progress_shows_active_package_and_call_counts(capsys) -> None:
    printer = inventory_progress.make_cli_progress_printer()
    printer({"phase": "start", "phase_label": "Collecting packages"})
    printer(
        {
            "phase": "progress",
            "processed": 5,
            "total": 10,
            "elapsed_seconds": 72.0,
            "split_processed": 1,
            "current_package": "com.google.android.apps.messaging",
            "current_stage": "pm dump",
            "path_calls_completed": 6,
            "metadata_calls_completed": 5,
            "active": True,
        }
    )
    out = colors.strip(capsys.readouterr().out)
    assert "path 6/10" in out
    assert "meta 5/10" in out
    assert "active pm dump: com.google.android.apps.messaging" in out


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


def test_menu_utils_print_section_and_metrics_use_readable_output(capsys) -> None:
    menu_utils.print_section("Current settings")
    menu_utils.print_metrics([("Theme", "blackhat-night"), ("Color output", "on")])
    out = colors.strip(capsys.readouterr().out)
    assert "Current settings" in out
    assert "Theme" in out
    assert "blackhat-night" in out
    assert "Color output" in out


def test_menu_utils_print_hint_wraps_cleanly(capsys) -> None:
    menu_utils.print_hint(
        "Choose a darker high-contrast theme for demos, or use auto to follow the terminal environment."
    )
    out = colors.strip(capsys.readouterr().out)
    assert "Choose a darker high-contrast theme for demos" in out
