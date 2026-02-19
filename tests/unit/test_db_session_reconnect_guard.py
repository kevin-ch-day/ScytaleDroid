from __future__ import annotations

from scytaledroid.Database.db_core import session


class _DummyEngine:
    def __init__(self, *, in_txn: bool) -> None:
        self._in_txn = in_txn
        self.reconnect_calls = 0
        self.closed = False

    def in_transaction(self) -> bool:
        return self._in_txn

    def reconnect(self) -> None:
        self.reconnect_calls += 1

    def close(self) -> None:
        self.closed = True


def test_get_current_engine_skips_reconnect_when_in_transaction() -> None:
    original_engine = session._STATE.engine
    original_depth = session._STATE.depth
    try:
        engine = _DummyEngine(in_txn=True)
        session._STATE.engine = engine
        session._STATE.depth = 1
        current = session.get_current_engine()
        assert current is engine
        assert engine.reconnect_calls == 0
    finally:
        session._STATE.engine = original_engine
        session._STATE.depth = original_depth


def test_get_current_engine_reconnects_when_not_in_transaction() -> None:
    original_engine = session._STATE.engine
    original_depth = session._STATE.depth
    try:
        engine = _DummyEngine(in_txn=False)
        session._STATE.engine = engine
        session._STATE.depth = 1
        current = session.get_current_engine()
        assert current is engine
        assert engine.reconnect_calls == 1
    finally:
        session._STATE.engine = original_engine
        session._STATE.depth = original_depth


def test_database_session_disallows_fresh_nested_connection() -> None:
    with session.database_session():
        try:
            with session.database_session(reuse_connection=False):
                raise AssertionError("expected RuntimeError for nested reuse_connection=False")
        except RuntimeError as exc:
            assert "reuse_connection=False" in str(exc)
