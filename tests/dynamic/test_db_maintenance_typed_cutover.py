from __future__ import annotations

from scytaledroid.DynamicAnalysis.storage import db_maintenance as m


def test_find_dangling_dynamic_static_links_uses_typed_static_run_expression(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_run_sql(sql, *_args, **_kwargs):
        captured["sql"] = sql
        return []

    monkeypatch.setattr(m, "run_sql", _fake_run_sql)

    rows = m.find_dangling_dynamic_static_links()

    assert rows == []
    sql = str(captured["sql"])
    assert "ds.static_run_id_u" in sql
    assert "CAST(ds.static_run_id AS UNSIGNED)" in sql


def test_clear_dangling_dynamic_static_links_clears_legacy_and_typed_columns(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_run_sql(sql, params=(), **_kwargs):
        seen.setdefault("count_sql", sql)
        seen.setdefault("count_params", params)
        return (2,)

    def _fake_run_sql_write(sql, params=(), **_kwargs):
        seen["write_sql"] = sql
        seen["write_params"] = params

    monkeypatch.setattr(m, "run_sql", _fake_run_sql)
    monkeypatch.setattr(m, "run_sql_write", _fake_run_sql_write)

    repaired = m.clear_dangling_dynamic_static_links(["run-a", "run-b"])

    assert repaired == 2
    count_sql = str(seen["count_sql"])
    write_sql = str(seen["write_sql"])
    assert "ds.static_run_id_u" in count_sql
    assert "CAST(ds.static_run_id AS UNSIGNED)" in count_sql
    assert "SET ds.static_run_id = NULL," in write_sql
    assert "ds.static_run_id_u = NULL" in write_sql

