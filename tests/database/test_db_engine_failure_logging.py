from __future__ import annotations

import sqlite3

import pytest

from scytaledroid.Database.db_core import db_engine


class _FakeLogger:
    def __init__(self) -> None:
        self.warning_calls: list[tuple[str, dict[str, object]]] = []

    def warning(self, message: str, *, extra=None, **_kwargs) -> None:  # noqa: ANN001
        self.warning_calls.append((message, dict(extra or {})))

    def error(self, *_args, **_kwargs) -> None:  # noqa: ANN001
        raise AssertionError("unexpected error log")

    def debug(self, *_args, **_kwargs) -> None:  # noqa: ANN001
        raise AssertionError("unexpected debug log")


def test_sqlite_operational_logging_includes_sql_fields(monkeypatch) -> None:
    fake_log = _FakeLogger()
    monkeypatch.setattr(db_engine, "_LOG", fake_log)

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    with pytest.raises(db_engine.DatabaseError):
        db_engine._execute(  # noqa: SLF001 - targeted logging contract
            cursor,
            "SELECT * FROM missing_table WHERE id = %s",
            (1,),
            query_name="test.sqlite.failure",
            context={"op": "probe"},
            many=False,
        )

    assert len(fake_log.warning_calls) == 1
    message, extra = fake_log.warning_calls[0]
    assert message == "db.exec.sqlite_operational"
    assert extra["query"] == "test.sqlite.failure"
    assert extra["op"] == "probe"
    assert extra["sql_preview"] == "SELECT * FROM missing_table WHERE id = %s"
    assert isinstance(extra["sql_sha1"], str)
    assert len(extra["sql_sha1"]) == 40
