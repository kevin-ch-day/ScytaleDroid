"""Guards on permission-risk backfill vs in-flight static runs."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from scytaledroid.Database.db_utils.action_groups import risk_actions


def test_count_inflight_static_analysis_runs_parses_scalar() -> None:
    calls: list[str] = []

    def run_sql(sql: str, **_kw: Any) -> list[int]:
        calls.append(sql)
        return [7]

    core_q = SimpleNamespace(run_sql=run_sql)
    assert risk_actions.count_inflight_static_analysis_runs(core_q=core_q) == 7
    assert "static_analysis_runs" in calls[0]
    assert "STARTED" in calls[0]


@pytest.fixture
def noop_status_messages() -> SimpleNamespace:
    return SimpleNamespace(status=lambda msg, level="info": msg)


@pytest.fixture(autouse=True)
def patch_spr_ensure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_func.static_analysis.static_permission_risk.ensure_table_vnext",
        lambda: True,
    )


def test_backfill_skips_writes_when_user_declines_after_inflight_prompt(
    monkeypatch: pytest.MonkeyPatch, noop_status_messages: SimpleNamespace
) -> None:
    writes: list[str] = []

    def run_sql(sql: str, fetch: str = "none", **_kw: Any) -> Any:
        if fetch == "one" and "FROM static_analysis_runs" in sql and "COUNT(*)" in sql and "STARTED" in sql:
            return [2]
        if fetch == "one" and "COUNT(*)" in sql and "FROM risk_scores" in sql:
            return [0]
        if fetch == "one" and "COUNT(*)" in sql and "static_permission_risk_vnext" in sql:
            return [0]
        return None

    def run_sql_write(sql: str, **_kw: Any) -> None:
        writes.append(sql)

    core_q = SimpleNamespace(run_sql=run_sql, run_sql_write=run_sql_write)
    prompts = iter([True, False])

    def prompt_yes_no(_msg: str, default: bool = False) -> bool:
        return next(prompts)

    risk_actions.backfill_static_permission_risk_vnext(
        core_q=core_q,
        prompt_utils=SimpleNamespace(
            prompt_yes_no=prompt_yes_no,
            press_enter_to_continue=lambda: None,
        ),
        status_messages=noop_status_messages,
    )
    assert writes == []


def test_backfill_proceeds_when_inflight_cleared_before_second_check(
    noop_status_messages: SimpleNamespace,
) -> None:
    writes: list[str] = []
    inflight_reads = [2, 0]

    def run_sql(sql: str, fetch: str = "none", **_kw: Any) -> Any:
        if fetch == "one" and "FROM static_analysis_runs" in sql and "COUNT(*)" in sql and "STARTED" in sql:
            return [inflight_reads.pop(0)]
        if fetch == "one" and "COUNT(*)" in sql and "FROM risk_scores" in sql:
            return [0]
        if fetch == "one" and "COUNT(*)" in sql and "static_permission_risk_vnext" in sql:
            return [0]
        return None

    def run_sql_write(sql: str, **_kw: Any) -> None:
        writes.append(sql)

    core_q = SimpleNamespace(run_sql=run_sql, run_sql_write=run_sql_write)

    risk_actions.backfill_static_permission_risk_vnext(
        core_q=core_q,
        prompt_utils=SimpleNamespace(
            prompt_yes_no=lambda *_a, **_k: True,
            press_enter_to_continue=lambda: None,
        ),
        status_messages=noop_status_messages,
    )
    assert len(writes) == 2
    assert any("INSERT INTO risk_scores" in w for w in writes)
    assert any("INSERT INTO static_permission_risk_vnext" in w for w in writes)


def test_backfill_writes_when_inflight_but_operator_confirms_twice(
    noop_status_messages: SimpleNamespace,
) -> None:
    writes: list[str] = []

    def run_sql(sql: str, fetch: str = "none", **_kw: Any) -> Any:
        if fetch == "one" and "FROM static_analysis_runs" in sql and "COUNT(*)" in sql and "STARTED" in sql:
            return [3]
        if fetch == "one" and "COUNT(*)" in sql and "FROM risk_scores" in sql:
            return [0]
        if fetch == "one" and "COUNT(*)" in sql and "static_permission_risk_vnext" in sql:
            return [0]
        return None

    def run_sql_write(sql: str, **_kw: Any) -> None:
        writes.append(sql)

    core_q = SimpleNamespace(run_sql=run_sql, run_sql_write=run_sql_write)
    answers = iter([True, True])

    def prompt_yes_no(_msg: str, default: bool = False) -> bool:
        return next(answers)

    risk_actions.backfill_static_permission_risk_vnext(
        core_q=core_q,
        prompt_utils=SimpleNamespace(
            prompt_yes_no=prompt_yes_no,
            press_enter_to_continue=lambda: None,
        ),
        status_messages=noop_status_messages,
    )
    assert len(writes) == 2
