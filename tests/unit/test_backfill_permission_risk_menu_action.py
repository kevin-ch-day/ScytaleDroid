from __future__ import annotations

from scytaledroid.Database.db_utils import menu_actions


def test_backfill_permission_risk_cancelled(monkeypatch):
    called = {"sql_write": 0}
    monkeypatch.setattr(menu_actions.prompt_utils, "prompt_yes_no", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(menu_actions.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.menu_actions.core_q.run_sql_write",
        lambda *_args, **_kwargs: called.__setitem__("sql_write", called["sql_write"] + 1),
    )

    menu_actions.backfill_static_permission_risk_vnext()
    assert called["sql_write"] == 0


def test_backfill_permission_risk_runs_both_backfill_writes(monkeypatch):
    state = {"writes": []}
    monkeypatch.setattr(menu_actions.prompt_utils, "prompt_yes_no", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(menu_actions.prompt_utils, "press_enter_to_continue", lambda: None)
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.menu_actions.core_q.run_sql",
        lambda *_args, **_kwargs: (0,),
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.menu_actions.core_q.run_sql_write",
        lambda sql, *_args, **_kwargs: state["writes"].append(sql) or 1,
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_func.static_analysis.static_permission_risk.ensure_table_vnext",
        lambda: True,
    )

    menu_actions.backfill_static_permission_risk_vnext()
    assert len(state["writes"]) == 3
    assert "INSERT INTO risk_scores" in state["writes"][0]
    assert "INSERT INTO risk_scores" in state["writes"][1]
    assert "INSERT INTO static_permission_risk_vnext" in state["writes"][2]


def test_audit_static_risk_coverage_reads_expected_metrics(monkeypatch):
    calls = {"sql": 0}

    def _sql(*_args, **_kwargs):
        calls["sql"] += 1
        if _kwargs.get("fetch") == "all":
            return []
        return (0,)

    monkeypatch.setattr("scytaledroid.Database.db_utils.menu_actions.core_q.run_sql", _sql)
    monkeypatch.setattr(menu_actions.prompt_utils, "press_enter_to_continue", lambda: None)

    menu_actions.audit_static_risk_coverage()
    assert calls["sql"] >= 5
