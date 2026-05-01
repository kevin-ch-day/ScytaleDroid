from __future__ import annotations

import pytest
from pymysql import err

from scytaledroid.Database.db_core import db_engine


class _Conn:
    def __init__(self, *, autocommit: bool) -> None:
        self._autocommit = autocommit
        self.ping_calls = 0

    def get_autocommit(self) -> bool:
        return self._autocommit

    def ping(self, reconnect: bool = False) -> None:
        self.ping_calls += 1


class _TxnConn:
    def __init__(self) -> None:
        self.open = True
        self._autocommit = True
        self.autocommit_calls: list[bool] = []
        self.commit_calls = 0
        self.rollback_calls = 0

    def get_autocommit(self) -> bool:
        return self._autocommit

    def autocommit(self, value: bool) -> None:
        self._autocommit = bool(value)
        self.autocommit_calls.append(bool(value))

    def commit(self) -> None:
        self.commit_calls += 1

    def rollback(self) -> None:
        self.rollback_calls += 1

    def ping(self, reconnect: bool = False) -> None:  # noqa: ARG002
        return None

    def close(self) -> None:
        return None


class _Cursor:
    def __init__(self, connection: _Conn, failures_before_success: int) -> None:
        self.connection = connection
        self._remaining = failures_before_success
        self.execute_calls = 0

    def execute(self, _sql, _params) -> None:
        self.execute_calls += 1
        if self._remaining > 0:
            self._remaining -= 1
            raise err.OperationalError(2013, "Lost connection to MySQL server during query")

    def executemany(self, _sql, _params) -> None:  # pragma: no cover - not used here
        raise NotImplementedError


def test_transient_error_inside_transaction_does_not_reconnect_or_retry(monkeypatch):
    monkeypatch.setattr(db_engine.time, "sleep", lambda *_a, **_k: None)
    conn = _Conn(autocommit=False)
    cursor = _Cursor(conn, failures_before_success=1)

    with pytest.raises(db_engine.TransientDbError):
        db_engine._execute(  # noqa: SLF001 - unit-test internal retry contract
            cursor,
            "SELECT 1",
            (),
            query_name="unit.test",
            context=None,
            many=False,
        )

    assert conn.ping_calls == 0
    assert cursor.execute_calls == 1


def test_transient_error_outside_transaction_retries_and_reconnects(monkeypatch):
    monkeypatch.setattr(db_engine.time, "sleep", lambda *_a, **_k: None)
    conn = _Conn(autocommit=True)
    cursor = _Cursor(conn, failures_before_success=1)

    db_engine._execute(  # noqa: SLF001 - unit-test internal retry contract
        cursor,
        "SELECT 1",
        (),
        query_name="unit.test",
        context=None,
        many=False,
    )

    assert conn.ping_calls == 1
    assert cursor.execute_calls == 2


def test_database_engine_transaction_depth_marks_in_transaction() -> None:
    engine = db_engine.DatabaseEngine()
    try:
        assert engine.in_transaction() is False
        with engine.transaction():
            assert engine.in_transaction() is True
        assert engine.in_transaction() is False
    finally:
        engine.close()


def test_nested_transaction_uses_outer_boundary_only() -> None:
    engine = db_engine.DatabaseEngine()
    conn = _TxnConn()
    engine._connection = conn  # noqa: SLF001 - unit-test controlled injection
    engine._dialect = "mysql"  # noqa: SLF001 - keep test deterministic
    try:
        with engine.transaction():
            assert engine.in_transaction() is True
            with engine.transaction():
                assert engine.in_transaction() is True
            assert engine.in_transaction() is True
        assert engine.in_transaction() is False
    finally:
        engine.close()

    assert conn.commit_calls == 1
    assert conn.rollback_calls == 0
    assert conn.autocommit_calls == [False, True]
