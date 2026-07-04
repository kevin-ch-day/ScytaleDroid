from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import colors, ui_prefs
from scytaledroid.Utils.DisplayUtils.colors import environment
from scytaledroid.Utils.DisplayUtils.theme_preview import format_theme_preview


def test_set_theme_updates_active_palette() -> None:
    original = colors.current_palette_name()
    try:
        selected = ui_prefs.set_theme("fedora-light")
        assert selected == "fedora-light"
        assert colors.current_palette_name() == "fedora-light"
        assert ui_prefs.get_theme() == "fedora-light"
    finally:
        colors.set_palette_by_name(original)


def test_reset_theme_auto_returns_valid_palette() -> None:
    ui_prefs.set_theme("fedora-light")
    selected = ui_prefs.reset_theme_auto()
    assert selected in colors.available_palettes()


def test_theme_preview_includes_name_and_severity_scale() -> None:
    original = colors.current_palette_name()
    try:
        colors.set_palette_by_name("fedora-dark")
        rendered = colors.strip(format_theme_preview(title="Preview"))
        assert "Preview: fedora-dark" in rendered
        assert "Severity scale:" in rendered
    finally:
        colors.set_palette_by_name(original)


def test_detect_palette_name_prefers_fedora_dark_on_fedora_host(monkeypatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_UI_THEME", raising=False)
    monkeypatch.delenv("SCYTALE_UI_THEME", raising=False)
    monkeypatch.delenv("SCYTALE_UI_HIGH_CONTRAST", raising=False)
    monkeypatch.delenv("GTK_THEME", raising=False)
    monkeypatch.delenv("COLORFGBG", raising=False)
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "Fedora")

    selected = environment.detect_palette_name(lambda value: value)

    assert selected == "fedora-dark"
