from scytaledroid.Utils.DisplayUtils import colors


def test_available_palettes_exposes_presets():
    palettes = colors.available_palettes()
    assert "fedora-dark" in palettes
    assert "fedora-light" in palettes
    assert "high-contrast" in palettes


def test_palette_switch_via_environment(monkeypatch):
    original_name = colors.current_palette_name()

    monkeypatch.setenv("SCYTALE_UI_THEME", "high-contrast")
    colors.reset_palette()
    try:
        assert colors.current_palette_name() == "high-contrast"
        assert colors.get_palette().text[0] == "1"

        monkeypatch.setenv("SCYTALE_UI_THEME", "fedora-light")
        colors.reset_palette()
        assert colors.current_palette_name() == "fedora-light"
        assert colors.get_palette().text == ("38;5;236",)
    finally:
        monkeypatch.delenv("SCYTALE_UI_THEME", raising=False)
        colors.reset_palette()
        assert colors.current_palette_name() == original_name
