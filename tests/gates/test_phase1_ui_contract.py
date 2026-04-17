from __future__ import annotations

from types import SimpleNamespace

import pytest

import main as app_main
from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.DeviceAnalysis.device_menu import dashboard
from scytaledroid.Utils.DisplayUtils import status_messages


pytestmark = [pytest.mark.contract, pytest.mark.ui_contract, pytest.mark.gate]


def test_main_menu_uses_phase1_platform_labels(monkeypatch) -> None:
    rendered = []

    monkeypatch.setattr(app_main, "ensure_db_ready", lambda: None)
    monkeypatch.setattr(
        schema_gate,
        "check_base_schema",
        lambda: (True, "ready", ""),
    )
    monkeypatch.setattr(app_main, "_print_tier1_status_banner", lambda: {})
    monkeypatch.setattr(app_main.menu_utils, "print_header", lambda *_a, **_k: None)
    monkeypatch.setattr(app_main.menu_utils, "render_menu", lambda spec: rendered.append(spec))
    monkeypatch.setattr(app_main.prompt_utils, "get_choice", lambda *_a, **_k: "0")
    monkeypatch.setattr(app_main.status_messages, "print_status", lambda *_a, **_k: None)
    monkeypatch.setattr(app_main.status_messages, "print_strip", lambda *_a, **_k: None)

    app_main.main_menu()

    assert rendered, "main menu should render a menu spec"
    labels = [item.label for item in rendered[0].items]
    assert labels == [
        "Device Inventory & Harvest",
        "Static Analysis Pipeline",
        "Dynamic Analysis",
        "API server",
        "Reporting & Exports",
        "Database tools",
        "Governance & Readiness",
        "Evidence & Workspace",
        "APK library",
        "About ScytaleDroid",
    ]


def test_blocked_and_non_root_status_contract(monkeypatch) -> None:
    palette = SimpleNamespace(
        success=("SUCCESS",),
        warning=("WARNING",),
        error=("ERROR",),
        blocked=("BLOCKED",),
        info=("INFO",),
        muted=("MUTED",),
    )

    monkeypatch.setattr(dashboard.colors, "get_palette", lambda: palette)
    monkeypatch.setattr(dashboard.colors, "colors_enabled", lambda: True)
    monkeypatch.setattr(dashboard.colors, "apply", lambda text, style, bold=False: f"<{','.join(style)}>{text}</>")

    blocked_line = status_messages.status("blocked by policy", level="blocked")
    non_root_badge = dashboard._root_badge("NO")

    assert "[BLOCKED]" in blocked_line
    assert "blocked by policy" in blocked_line
    assert any(marker in blocked_line for marker in ("⊘", "-"))

    assert "<INFO>" in non_root_badge
    assert "NON-ROOT" in non_root_badge
    assert "<WARNING>" not in non_root_badge
