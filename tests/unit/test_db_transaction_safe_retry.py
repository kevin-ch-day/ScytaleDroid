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


def test_transient_error_outside_transaction_does_not_reuse_cursor(monkeypatch):
    monkeypatch.setattr(db_engine.time, "sleep", lambda *_a, **_k: None)
    conn = _Conn(autocommit=True)
    cursor = _Cursor(conn, failures_before_success=1)

    with pytest.raises(db_engine.TransientDbError) as excinfo:
        db_engine._execute(  # noqa: SLF001 - unit-test internal retry contract
            cursor,
            "SELECT 1",
            (),
            query_name="unit.test",
            context=None,
            many=False,
        )

    assert excinfo.value.errno == 2013
    assert conn.ping_calls == 0
    assert cursor.execute_calls == 1


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


class _RetryConn:
    def __init__(self) -> None:
        self.open = True
        self._autocommit = True
        self.ping_calls = 0
        self.execute_calls = 0
        self.commit_calls = 0

    def get_autocommit(self) -> bool:
        return self._autocommit

    def ping(self, reconnect: bool = False) -> None:  # noqa: ARG002
        self.ping_calls += 1

    def cursor(self, *_args, **_kwargs):
        return _RetryCursor(self)

    def commit(self) -> None:
        self.commit_calls += 1

    def close(self) -> None:
        self.open = False


class _RetryCursor:
    def __init__(self, connection: _RetryConn) -> None:
        self.connection = connection

    def execute(self, _sql, _params) -> None:
        self.connection.execute_calls += 1
        if self.connection.execute_calls == 1:
            raise err.OperationalError(2013, "Lost connection to MySQL server during query")

    def fetchone(self):
        return (1,)

    def close(self) -> None:
        return None


def test_transaction_baseexception_rolls_back_and_restores_autocommit() -> None:
    engine = db_engine.DatabaseEngine()
    conn = _TxnConn()
    engine._connection = conn  # noqa: SLF001 - unit-test controlled injection
    engine._dialect = "mysql"  # noqa: SLF001 - keep test deterministic
    try:
        with pytest.raises(KeyboardInterrupt):
            with engine.transaction():
                raise KeyboardInterrupt()
        assert engine.in_transaction() is False
        assert conn.commit_calls == 0
        assert conn.rollback_calls == 1
        assert conn.autocommit_calls == [False, True]
    finally:
        engine.close()


def test_engine_fetch_retries_transient_with_fresh_cursor(monkeypatch) -> None:
    monkeypatch.setattr(db_engine.time, "sleep", lambda *_a, **_k: None)
    engine = db_engine.DatabaseEngine()
    conn = _RetryConn()
    engine._connection = conn  # noqa: SLF001 - unit-test controlled injection
    engine._dialect = "mysql"  # noqa: SLF001 - keep test deterministic
    try:
        row = engine.fetch_one("SELECT 1")
        assert row == (1,)
        assert conn.execute_calls == 2
        assert conn.ping_calls == 1
    finally:
        engine.close()


def test_read_only_guard_rejects_comment_prefixed_writes() -> None:
    engine = db_engine.DatabaseEngine()
    try:
        engine.as_reader()
        with pytest.raises(db_engine.DatabaseError, match="read-only"):
            engine.execute("-- note\nINSERT INTO t VALUES (1)")
    finally:
        engine.close()


def test_ensure_db_ready_closes_engine_after_probe(monkeypatch) -> None:
    closed = {"n": 0}

    class FakeEngine:
        def fetch_one(self, *_args, **_kwargs):
            return ("ok",)

        def close(self) -> None:
            closed["n"] += 1

    monkeypatch.setitem(db_engine.DB_CONFIG, "engine", "mysql")
    monkeypatch.setitem(db_engine.DB_CONFIG, "user", "u")
    monkeypatch.setitem(db_engine.DB_CONFIG, "host", "h")
    monkeypatch.setitem(db_engine.DB_CONFIG, "port", 3306)
    monkeypatch.setitem(db_engine.DB_CONFIG, "database", "d")
    monkeypatch.setattr(db_engine, "DatabaseEngine", FakeEngine)
    db_engine.ensure_db_ready(require_schema=False)
    assert closed["n"] == 1
