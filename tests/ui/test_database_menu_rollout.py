from __future__ import annotations

import importlib
from dataclasses import fields
from types import SimpleNamespace

import pytest

from scytaledroid.Database.db_utils.health_checks.analysis_integrity import AnalysisIntegritySummary


pytestmark = [pytest.mark.ui_contract]


def test_database_menu_renders_shared_sections(monkeypatch, capsys):
    menu_module = importlib.import_module("scytaledroid.Database.db_utils.database_menu")

    monkeypatch.setattr(menu_module, "maybe_clear_screen", lambda: None)
    monkeypatch.setattr(menu_module.diagnostics, "get_schema_version", lambda: "0.2.5")
    monkeypatch.setattr(menu_module.diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(menu_module.diagnostics, "get_server_info", lambda: {"database": "scytaledroid_test"})
    rendered_labels: list[str] = []

    def capture_render(spec, *_a, **_k):
        rendered_labels.extend(item.label for item in spec.items)

    monkeypatch.setattr(menu_module.menu_utils, "render_menu", capture_render)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.database_menu()

    out = capsys.readouterr().out
    assert "Database Tools" in out
    assert "Database State" in out
    assert "Read-Only Diagnostics" in out
    assert any("Database health & integrity" in label for label in rendered_labels)
    assert any("Permission Intel & snapshot governance" in label for label in rendered_labels)
    assert any("Static & registry diagnostics" in label for label in rendered_labels)
    assert "Maintenance, repair, and migrations" in out
    assert "Connection" in out
    assert "Target DB" in out


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
    monkeypatch.setattr(
        menu_module.diagnostics,
        "check_required_tables",
        lambda tables: {t: True for t in tables},
    )

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
    assert ("Session links", "0") in captured[1]
    assert ("Findings summary", "0") in captured[1]


def test_session_downstream_counts_skips_legacy_runs_when_table_absent(monkeypatch):
    from scytaledroid.Database.db_utils.menus import query_runner as menu_module

    def _presence(tables):
        return {t: (t != "runs") for t in tables}

    monkeypatch.setattr(menu_module.diagnostics, "check_required_tables", _presence)

    def _run_read_only(sql, params=(), fetch=None, dictionary=False, **_kwargs):
        if "FROM runs" in sql:
            raise AssertionError("runs COUNT should be skipped when table absent")
        if "FROM static_session_run_links" in sql:
            return (2,)
        if "FROM risk_scores" in sql:
            return (1,)
        if "FROM static_findings_summary" in sql:
            return (0,)
        if "FROM static_string_summary" in sql:
            return (0,)
        raise AssertionError(sql)

    monkeypatch.setattr(menu_module, "_run_read_only", _run_read_only)

    out = menu_module._session_downstream_counts("sess-x")
    assert out["legacy_runs"] is None
    assert out["session_links"] == 2
    assert out["legacy_risk"] == 1


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

    kw = {f.name: None for f in fields(AnalysisIntegritySummary)}
    kw["static_dynamic_summary_source"] = "stub"
    kw["legacy_non_utf8_package_tables"] = ()
    kw["missing_schema_objects"] = ()
    analysis_stub = AnalysisIntegritySummary(**kw)

    monkeypatch.setattr(menu_module, "fetch_analysis_integrity_summary", lambda: analysis_stub)
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
    from scytaledroid.Database.db_utils.static_run_governance_checks import StaticRunGovernanceCounts

    monkeypatch.setattr(
        menu_module,
        "fetch_static_run_governance_counts",
        lambda *_a, **_k: StaticRunGovernanceCounts(0, 0, 0),
    )
    monkeypatch.setattr(menu_module.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(
        menu_module.intel_db,
        "describe_target",
        lambda: {"database": "pi_db", "source": "env"},
    )
    monkeypatch.setattr(menu_module, "list_operational_managed_tables", lambda: [])
    monkeypatch.setattr(menu_module.intel_db, "governance_snapshot_count", lambda: 1)
    monkeypatch.setattr(menu_module.intel_db, "governance_row_count", lambda: 1828)
    monkeypatch.setattr(menu_module, "governance_ready", lambda: (True, "ok"))
    monkeypatch.setattr(menu_module.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None)

    menu_module.run_health_summary()

    out = capsys.readouterr().out
    assert "DB Health Summary" in out
    assert "Run status" in out
    assert "Static run class / handoff invariants" in out
    assert "governance_ready (static CLI / paper-grade gate): True" in out
