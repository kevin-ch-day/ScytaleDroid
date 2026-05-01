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
    monkeypatch.setattr(menu_module.diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(menu_module.diagnostics, "get_server_info", lambda: {"database": "scytaledroid_test"})
    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.database_menu()

    out = capsys.readouterr().out
    assert "Database Tools" in out
    assert "Database State" in out
    assert "Read-Only Diagnostics" in out
    assert "Maintenance, repair, and migrations" in out
    assert "Connection" in out
    assert "Target DB" in out


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

    captured = {}
    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda spec, *_a, **_k: captured.setdefault("spec", spec))
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.run_query_menu()

    out = capsys.readouterr().out
    assert "Curated Read-only Queries" in out
    assert "Actions" in out
    assert captured["spec"].items[0] == ("1", "Active static session")


def test_query_runner_active_static_session_renders_compact_status(monkeypatch, capsys, tmp_path):
    from scytaledroid.Database.db_utils.menus import query_runner as menu_module

    archive_dir = tmp_path / "static_analysis" / "reports" / "archive" / "sess-1"
    archive_dir.mkdir(parents=True, exist_ok=True)
    (archive_dir / "a.json").write_text("{}", encoding="utf-8")
    (archive_dir / "b.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(menu_module.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(menu_module.prompt_utils, "press_enter_to_continue", lambda *_a, **_k: None)

    def _run_read_only(sql, params=(), fetch=None, dictionary=False, **_kwargs):
        if "WHERE UPPER(COALESCE(status, '')) = 'STARTED'" in sql:
            return {
                "session_stamp": "sess-1",
                "started_runs": 21,
                "completed_runs": 0,
                "failed_runs": 0,
                "started_at": "2026-04-28 20:40:00",
            }
        if "FROM static_session_run_links" in sql:
            return (0,)
        if "FROM risk_scores" in sql:
            return (0,)
        if "FROM runs WHERE session_stamp=%s" in sql:
            return (0,)
        if "FROM static_findings_summary" in sql:
            return (0,)
        if "FROM static_string_summary" in sql:
            return (0,)
        raise AssertionError(sql)

    monkeypatch.setattr(menu_module, "_run_read_only", _run_read_only)

    captured: list[list[tuple[str, object]]] = []
    monkeypatch.setattr(menu_module.menu_utils, "print_metrics", lambda items: captured.append(items))

    menu_module.show_active_static_session_status()

    out = capsys.readouterr().out
    assert "Active static session" in out
    assert captured[0][0] == ("Session", "sess-1")
    assert ("Archive reports", 2) in captured[0]
    assert ("Session links", 0) in captured[1]
    assert ("Findings summary", 0) in captured[1]


def test_query_runner_package_lineage_uses_canonical_run_headers(monkeypatch, capsys):
    from scytaledroid.Database.db_utils.menus import query_runner as menu_module

    monkeypatch.setattr(menu_module.prompt_utils, "prompt_text", lambda *_a, **_k: "org.example.app")
    monkeypatch.setattr(menu_module.prompt_utils, "press_enter_to_continue", lambda *_a, **_k: None)
    monkeypatch.setattr(
        menu_module,
        "_run_read_only",
        lambda *_a, **_k: [
            {
                "static_run_id": 549,
                "session_stamp": "sess-1",
                "session_label": "signal-full",
                "version_name": "8.6.2",
                "version_code": 168201,
                "profile": "Full",
                "status": "FAILED",
                "created_at": "2026-04-27 22:20:32",
                "findings_total": 29,
                "is_canonical": 1,
            }
        ],
    )

    captured: list[tuple[list[str], list[list[str]]]] = []

    def _capture_table(headers, rows, *args, **kwargs):
        captured.append((headers, rows))

    monkeypatch.setattr(menu_module.table_utils, "render_table", _capture_table)

    menu_module.prompt_runs_for_package()

    out = capsys.readouterr().out
    assert "Canonical static runs for org.example.app" in out
    assert captured
    headers, rows = captured[0]
    assert headers == ["Static", "Status", "Created", "Canon"]
    assert rows[0][0] == "549"
    assert rows[0][1] == "FAILED"
    assert "Per-run details" in out
    assert "findings=29" in out


def test_query_runner_latest_session_snapshot_uses_canonical_run_headers(monkeypatch, capsys):
    from scytaledroid.Database.db_utils.menus import query_runner as menu_module

    monkeypatch.setattr(
        menu_module,
        "_run_read_only",
        lambda *_a, **_k: {
            "session_stamp": "qa-signal-full-1",
            "static_run_id": 557,
            "package_name": "org.thoughtcrime.securesms",
            "status": "COMPLETED",
            "created_at": "2026-04-28 05:00:00",
        },
    )
    monkeypatch.setattr(menu_module.prompt_utils, "press_enter_to_continue", lambda *_a, **_k: None)

    captured: list[list[tuple[str, object]]] = []

    def _capture_metrics(items):
        captured.append(items)

    monkeypatch.setattr(menu_module.menu_utils, "print_metrics", _capture_metrics)
    monkeypatch.setattr(menu_module, "_print_session_counts", lambda *_a, **_k: None)

    menu_module.show_latest_session()

    out = capsys.readouterr().out
    assert "Latest session snapshot" in out
    assert captured
    assert ("Static run", 557) in captured[0]
    assert ("Status", "COMPLETED") in captured[0]


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
    monkeypatch.setattr(menu_module.intel_db, "governance_snapshot_count", lambda: 1)
    monkeypatch.setattr(menu_module.intel_db, "governance_row_count", lambda: 1828)
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
    from scytaledroid.StaticAnalysis.cli.persistence.reports import session_diagnostics as menu_module

    captured: dict[str, object] = {}

    def _print_menu(options, **kwargs):
        captured["options"] = options
        captured["kwargs"] = kwargs

    monkeypatch.setattr(menu_module.menu_utils, "print_menu", _print_menu)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.render_static_diagnostics_menu()

    out = capsys.readouterr().out
    assert "Static Run History" in out
    assert "Actions" in out
    assert captured["kwargs"]["show_exit"] is True
    assert "7" in captured["options"]
    assert captured["options"]["7"] == "Latest static coverage"


def test_static_diagnostics_can_render_latest_coverage(monkeypatch, capsys):
    from scytaledroid.StaticAnalysis.cli.persistence.reports import session_diagnostics as menu_module

    def _run_sql(sql, params=(), fetch=None, **_kwargs):
        normalized = " ".join(str(sql).split()).lower()
        if "select session_stamp from static_analysis_runs order by id desc limit 1" in normalized:
            return ("sess-1",)
        if "select count(*) from static_analysis_runs where session_stamp=%s" in normalized:
            return (10,)
        if "sum(case when upper(coalesce(status,''))='completed'" in normalized:
            return (10,)
        if "from static_analysis_findings where run_id in" in normalized:
            return (77,)
        if "from static_permission_matrix where run_id in" in normalized:
            return (88,)
        if "from static_permission_risk_vnext where run_id in" in normalized:
            return (88,)
        if "from static_correlation_results where static_run_id in" in normalized and "distinct package_name" not in normalized:
            return (9,)
        if "from static_correlation_results where static_run_id in" in normalized and "distinct package_name" in normalized:
            return (8,)
        if "from static_provider_acl where session_stamp=%s" in normalized and "distinct package_name" not in normalized:
            return (5,)
        if "from static_provider_acl where session_stamp=%s" in normalized and "distinct package_name" in normalized:
            return (3,)
        if "from static_fileproviders where run_id in" in normalized and "distinct package_name" not in normalized:
            return (44,)
        if "from static_fileproviders where run_id in" in normalized and "distinct package_name" in normalized:
            return (12,)
        if "from permission_audit_snapshots where static_run_id in" in normalized:
            return (0,)
        if "from permission_audit_apps where static_run_id in" in normalized:
            return (0,)
        if "from static_session_run_links where session_stamp=%s" in normalized:
            return (10,)
        if "from web_static_dynamic_app_summary_cache where latest_static_session_stamp=%s" in normalized:
            return (10,)
        raise AssertionError(sql)

    monkeypatch.setattr(menu_module.core_q, "run_sql", _run_sql)
    monkeypatch.setattr(menu_module.prompt_utils, "press_enter_to_continue", lambda: None)

    menu_module._show_latest_static_coverage()

    out = capsys.readouterr().out
    assert "Latest static coverage" in out
    assert "Provider ACL" in out
    assert "5" in out
    assert "Permission audit snapshots" in out
    assert "missing" in out


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
