from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from scytaledroid.Database.db_core import db_queries


@dataclass
class _FakeDb:
    last_sql: str | None = None
    last_params: Any = None
    last_query_name: str | None = None
    last_context: Mapping[str, Any] | None = None

    def fetch_all_dict(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> list[dict[str, object]]:
        self.last_sql = sql
        self.last_params = params
        self.last_query_name = query_name
        self.last_context = context
        return [{"ok": True}]

    def execute_many(
        self,
        sql: str,
        rows: Any,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        self.last_sql = sql
        self.last_params = rows
        self.last_query_name = query_name
        self.last_context = context


def test_run_sql_adds_caller_hint_when_context_absent(monkeypatch) -> None:
    fake = _FakeDb()
    monkeypatch.setattr(db_queries, "_resolve_engine", lambda: fake)

    rows = db_queries.run_sql("SELECT 1", fetch="all_dict")

    assert rows == [{"ok": True}]
    assert fake.last_query_name == "run_sql.all_dict"
    assert fake.last_context is not None
    assert "caller" in fake.last_context
    assert "test_db_queries_caller_context.py:test_run_sql_adds_caller_hint_when_context_absent" in str(
        fake.last_context["caller"]
    )


def test_run_sql_preserves_existing_context_and_adds_caller_hint(monkeypatch) -> None:
    fake = _FakeDb()
    monkeypatch.setattr(db_queries, "_resolve_engine", lambda: fake)

    db_queries.run_sql("SELECT 1", fetch="all_dict", context={"op": "inspect"})

    assert fake.last_context is not None
    assert fake.last_context["op"] == "inspect"
    assert "caller" in fake.last_context


def test_run_sql_many_adds_caller_hint(monkeypatch) -> None:
    fake = _FakeDb()
    monkeypatch.setattr(db_queries, "_resolve_engine", lambda: fake)

    db_queries.run_sql_many("INSERT INTO demo VALUES (%s)", [(1,), (2,)])

    assert fake.last_query_name is None
    assert fake.last_context is not None
    assert "caller" in fake.last_context
