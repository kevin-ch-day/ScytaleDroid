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


def test_default_non_fedora_palette_uses_balanced_scytale_dark(monkeypatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_UI_THEME", raising=False)
    monkeypatch.delenv("SCYTALE_UI_THEME", raising=False)
    monkeypatch.delenv("SCYTALE_UI_HIGH_CONTRAST", raising=False)
    monkeypatch.delenv("GTK_THEME", raising=False)
    monkeypatch.delenv("COLORFGBG", raising=False)
    monkeypatch.setattr(environment, "_host_looks_like_fedora", lambda: False)

    selected = environment.detect_palette_name(lambda value: value)

    assert selected == "scytale-dark"


def test_default_palette_alias_resolves_to_scytale_dark() -> None:
    original = colors.current_palette_name()
    try:
        colors.set_palette_by_name("default")
        assert colors.current_palette_name() == "scytale-dark"
    finally:
        colors.set_palette_by_name(original)


def test_semantic_theme_roles_drive_status_and_severity_styles() -> None:
    from scytaledroid.Utils.DisplayUtils import severity, status_messages, summary_cards
    from scytaledroid.Utils.DisplayUtils.theme_roles import (
        SEVERITY_STYLE_ROLES,
        STATUS_STYLE_ROLES,
        delta_role,
        severity_role,
        status_roles,
    )

    assert status_roles("warn") == STATUS_STYLE_ROLES["warn"]
    assert status_roles("does-not-exist") == STATUS_STYLE_ROLES["info"]
    assert severity_role("p0") == SEVERITY_STYLE_ROLES["p0"]
    assert delta_role("changed") == "warning"

    assert "WARN" in colors.strip(status_messages.status("review", level="warn"))
    assert "UPDATED:2" in colors.strip(severity.format_delta_token("updated", 2))
    card = summary_cards.format_summary_card(
        "Severity",
        [summary_cards.summary_item("Critical", 1)],
    )
    assert "Critical" in colors.strip(card)
