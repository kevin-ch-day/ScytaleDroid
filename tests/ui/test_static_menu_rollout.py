from __future__ import annotations

import pytest


pytestmark = [pytest.mark.ui_contract]


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
