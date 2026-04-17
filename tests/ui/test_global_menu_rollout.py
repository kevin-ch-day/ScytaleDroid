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


def test_database_menu_renders_shared_sections(monkeypatch, capsys):
    menu_module = importlib.import_module("scytaledroid.Database.db_utils.database_menu")

    monkeypatch.setattr(menu_module, "maybe_clear_screen", lambda: None)
    monkeypatch.setattr(menu_module.diagnostics, "get_schema_version", lambda: "0.2.5")
    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.database_menu()

    out = capsys.readouterr().out
    assert "Database Tools" in out
    assert "Database State" in out
    assert "Readiness & Integrity" in out


def test_governance_menu_renders_shared_sections(monkeypatch, capsys, tmp_path):
    from scytaledroid.Utils.System import governance_inputs as menu_module

    monkeypatch.setattr(menu_module, "_ensure_workspace", lambda: tmp_path)
    monkeypatch.setattr(menu_module, "_latest_governance_status", lambda: ("missing", None, None, 0, None))
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.render_governance_inputs()

    out = capsys.readouterr().out
    assert "Governance & Readiness" in out
    assert "Governance Snapshot Bundle" in out
    assert "Actions" in out


def test_query_runner_menu_uses_shared_actions(monkeypatch, capsys):
    from scytaledroid.Database.db_utils.menus import query_runner as menu_module

    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.run_query_menu()

    out = capsys.readouterr().out
    assert "Curated Read-only Queries" in out
    assert "Actions" in out


def test_db_health_summary_uses_shared_sections(monkeypatch, capsys):
    from scytaledroid.Database.db_utils.menus import health_checks as menu_module

    monkeypatch.setattr(
        menu_module,
        "fetch_health_summary",
        lambda: SimpleNamespace(
            running_total=1,
            running_recent=0,
            ok_recent=2,
            failed_recent=0,
            aborted_recent=0,
            orphan_findings=0,
            orphan_samples=0,
            orphan_selected_samples=0,
            orphan_sample_sets=0,
            orphan_audit_apps=0,
        ),
    )
    monkeypatch.setattr(menu_module, "_column_exists", lambda *_a, **_k: False)
    monkeypatch.setattr(menu_module, "scalar", lambda *_a, **_k: 1)
    monkeypatch.setattr(menu_module.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None)

    menu_module.run_health_summary()

    out = capsys.readouterr().out
    assert "DB Health Summary" in out
    assert "Run status" in out


def test_api_menu_renders_runtime_state(monkeypatch, capsys):
    from scytaledroid.Api import menu as menu_module

    monkeypatch.setattr(
        menu_module,
        "api_status",
        lambda: SimpleNamespace(status="stopped", host="127.0.0.1", port=8000, detail="idle", running=False),
    )
    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.api_menu()

    out = capsys.readouterr().out
    assert "API Server" in out
    assert "Runtime State" in out
    assert "Actions" in out


def test_dynamic_state_summary_uses_shared_hint(monkeypatch, capsys):
    from scytaledroid.DynamicAnalysis import menu_reports as menu_module

    monkeypatch.setenv("SCYTALEDROID_UI_LEVEL", "")
    summary = SimpleNamespace(
        can_freeze=False,
        total_runs=1,
        paper_eligible_runs=0,
        first_failing_reason="NO_VALID_RUNS",
        report_path="output/report.json",
    )

    menu_module.run_state_summary_report(
        summary=summary,
        payload={},
        state_payload={},
        delta_rows=[],
        priorities=[],
    )

    out = capsys.readouterr().out
    assert "State Summary" in out
    assert "Compare tracker state" in out


def test_static_diagnostics_menu_uses_shared_actions(monkeypatch, capsys):
    from scytaledroid.StaticAnalysis.cli.reports import session_diagnostics as menu_module

    monkeypatch.setattr(menu_module.menu_utils, "print_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.render_static_diagnostics_menu()

    out = capsys.readouterr().out
    assert "Static Analysis Diagnostics" in out
    assert "Actions" in out


def test_static_scope_selection_uses_shared_actions(monkeypatch, capsys):
    from scytaledroid.StaticAnalysis.cli.flows import selection as menu_module

    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "3")

    result = menu_module.select_scope([])

    out = capsys.readouterr().out
    assert "Scope" in out
    assert "Actions" in out
    assert result.scope == "all"


def test_apk_library_menu_renders_summary_sections(monkeypatch, capsys):
    from scytaledroid.DeviceAnalysis import apk_library_menu as menu_module

    monkeypatch.setattr(menu_module.apk_library_service, "list_groups", lambda *args, **kwargs: [])
    monkeypatch.setattr(menu_module.static_scope_service, "count", lambda: 0)
    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.apk_library_menu()

    out = capsys.readouterr().out
    assert "APK Library" in out
    assert "Library Summary" in out
    assert "Actions" in out


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
