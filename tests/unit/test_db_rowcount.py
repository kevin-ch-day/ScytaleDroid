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

    def execute_with_rowcount(
        self,
        sql: str,
        params: Any | None = None,
        *,
        query_name: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> int:
        self.last_sql = sql
        self.last_params = params
        self.last_query_name = query_name
        self.last_context = context
        return 7


def test_run_sql_rowcount_delegates_to_engine(monkeypatch) -> None:
    fake = _FakeDb()
    monkeypatch.setattr(db_queries, "_resolve_engine", lambda: fake)

    rowcount = db_queries.run_sql_rowcount(
        "UPDATE table_x SET c=%s WHERE id=%s",
        (1, 2),
        query_name="rowcount.test",
        context={"op": "update"},
    )

    assert rowcount == 7
    assert fake.last_sql == "UPDATE table_x SET c=%s WHERE id=%s"
    assert fake.last_params == (1, 2)
    assert fake.last_query_name == "rowcount.test"
    assert fake.last_context == {"op": "update"}
