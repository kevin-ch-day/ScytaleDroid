from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from scytaledroid.Database.db_utils.action_groups import schema_actions


def test_ensure_dynamic_tier_column_fails_closed_on_non_mysql(monkeypatch, capsys) -> None:
    prompt_called = {"value": False}
    core_calls: list[str] = []

    result = schema_actions.ensure_dynamic_tier_column(
        db_config=SimpleNamespace(DB_CONFIG={"engine": "sqlite"}),
        diagnostics=SimpleNamespace(get_table_columns=lambda _table: []),
        core_q=SimpleNamespace(run_sql_write=lambda *_a, **_k: core_calls.append("write")),
        prompt_utils=SimpleNamespace(
            prompt_yes_no=lambda *_a, **_k: prompt_called.__setitem__("value", True) or True
        ),
        status_messages=SimpleNamespace(status=lambda message, level="info": f"{level}:{message}"),
        prompt_user=True,
    )

    out = capsys.readouterr().out
    assert result is False
    assert "only supported for MySQL/MariaDB backends" in out
    assert prompt_called["value"] is False
    assert core_calls == []


def test_ensure_dynamic_tier_migrations_logs_failure_on_exception(monkeypatch) -> None:
    writes: list[tuple[str, object | None, str | None]] = []
    core_q = SimpleNamespace(
        run_sql_write=lambda sql, params=None, query_name=None: writes.append((sql, params, query_name))
    )
    diagnostics = SimpleNamespace(get_schema_version=lambda: "0.2.5")

    monkeypatch.setattr(
        schema_actions,
        "ensure_dynamic_tier_column",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("tier boom")),
    )

    try:
        schema_actions.ensure_dynamic_tier_migrations(
            diagnostics=diagnostics,
            app_config=SimpleNamespace(APP_VERSION="2.1.1"),
            core_q=core_q,
            db_config=SimpleNamespace(DB_CONFIG={"engine": "mysql"}),
            prompt_utils=SimpleNamespace(prompt_yes_no=lambda *_a, **_k: True),
            status_messages=SimpleNamespace(status=lambda message, level="info": f"{level}:{message}"),
            prompt_user=False,
        )
    except RuntimeError as exc:
        assert str(exc) == "tier boom"
    else:
        raise AssertionError("expected migration exception to propagate")

    assert any("CREATE TABLE IF NOT EXISTS db_ops_log" in sql for sql, _params, _q in writes)
    log_inserts = [params for sql, params, query_name in writes if query_name == "db_utils.db_ops_log.insert"]
    assert log_inserts, "expected db_ops_log insert on failure"
    assert log_inserts[-1][0] == "tier1_schema_migrations"
    assert log_inserts[-1][-2] == 0
    assert log_inserts[-1][-1] == "tier boom"


def test_ensure_dynamic_tier_migrations_non_mysql_short_circuits_before_sql(monkeypatch, capsys) -> None:
    writes: list[tuple[str, object | None, str | None]] = []
    core_q = SimpleNamespace(
        run_sql_write=lambda sql, params=None, query_name=None: writes.append((sql, params, query_name))
    )

    result = schema_actions.ensure_dynamic_tier_migrations(
        diagnostics=SimpleNamespace(get_schema_version=lambda: "0.2.5"),
        app_config=SimpleNamespace(APP_VERSION="2.1.1"),
        core_q=core_q,
        db_config=SimpleNamespace(DB_CONFIG={"engine": "sqlite"}),
        prompt_utils=SimpleNamespace(prompt_yes_no=lambda *_a, **_k: True),
        status_messages=SimpleNamespace(status=lambda message, level="info": f"{level}:{message}"),
        prompt_user=False,
    )

    out = capsys.readouterr().out
    assert result is False
    assert "only supported for MySQL/MariaDB backends" in out
    assert writes == []
