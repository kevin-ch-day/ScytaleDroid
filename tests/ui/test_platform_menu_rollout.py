from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

pytestmark = [pytest.mark.ui_contract]


def test_device_hub_renders_shared_state(monkeypatch, capsys):
    from scytaledroid.DeviceAnalysis import device_hub_menu as menu_module

    monkeypatch.setattr(
        menu_module.device_service,
        "scan_devices",
        lambda: (
            [object()],
            [],
            [
                {
                    "serial": "ZY22JK89DR",
                    "model": "moto g 5G - 2024",
                    "manufacturer": "Motorola",
                    "android_release": "15",
                    "android_sdk": "35",
                    "is_rooted": "NO",
                }
            ],
            {},
        ),
    )
    monkeypatch.setattr(
        menu_module.device_service,
        "fetch_inventory_metadata",
        lambda _serial: SimpleNamespace(age_display="14m ago", package_count=546),
    )
    monkeypatch.setattr(menu_module.device_service, "set_active_serial", lambda _serial: False)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.devices_hub()

    out = capsys.readouterr().out
    assert "Device Inventory & Harvest" in out
    assert "Devices" in out


def test_governance_menu_renders_shared_sections(monkeypatch, capsys, tmp_path):
    from scytaledroid.Utils.System import governance_inputs as menu_module

    monkeypatch.setattr(menu_module, "_ensure_workspace", lambda: tmp_path)
    monkeypatch.setattr(
        menu_module, "_latest_governance_status", lambda: ("missing", None, None, 0, None)
    )
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.render_governance_inputs()

    out = capsys.readouterr().out
    assert "Governance & Readiness" in out
    assert "Governance Snapshot Bundle" in out
    assert "Actions" in out


def test_api_menu_renders_runtime_state(monkeypatch, capsys):
    from scytaledroid.Api import menu as menu_module

    monkeypatch.setattr(
        menu_module,
        "api_status",
        lambda: SimpleNamespace(
            status="stopped", host="127.0.0.1", port=8000, detail="idle", running=False
        ),
    )
    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.api_menu()

    out = capsys.readouterr().out
    assert "API Server" in out
    assert "Runtime State" in out
    assert "Actions" in out


def test_apk_library_menu_renders_summary_sections(monkeypatch, capsys):
    from scytaledroid.DeviceAnalysis import apk_library_menu as menu_module

    rendered = []
    monkeypatch.setattr(menu_module.apk_library_service, "list_groups", lambda *args, **kwargs: [])
    monkeypatch.setattr(menu_module.static_scope_service, "count", lambda: 0)
    monkeypatch.setattr(
        menu_module.menu_utils, "render_menu", lambda spec, *_a, **_k: rendered.append(spec)
    )
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.apk_library_menu()

    out = capsys.readouterr().out
    assert "APK Library" in out
    assert "Library Summary" in out
    assert "Actions" in out
    assert any(
        "Package lineage" in getattr(item, "label", "")
        for spec in rendered
        for item in getattr(spec, "items", [])
    )


def test_utilities_menu_uses_shared_actions(monkeypatch, capsys):
    menu_module = importlib.import_module("scytaledroid.Utils.System.utils_menu")

    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.utils_menu()

    out = capsys.readouterr().out
    assert "Utilities" in out
    assert "Actions" in out


def test_about_screen_uses_shared_sections(capsys):
    from scytaledroid.Utils.AboutApp.about_app import about_app
    from scytaledroid.Utils.DisplayUtils import prompt_utils

    original = prompt_utils.press_enter_to_continue
    prompt_utils.press_enter_to_continue = lambda *args, **kwargs: None
    try:
        about_app()
    finally:
        prompt_utils.press_enter_to_continue = original

    out = capsys.readouterr().out
    assert "About ScytaleDroid" in out
    assert "Application" in out
    assert "Mission" in out
    assert "Version" in out
