"""Connection lifecycle helpers for sharing database sessions."""

from __future__ import annotations

from contextlib import contextmanager
from threading import local
from typing import Iterator, Optional

from .db_engine import DatabaseEngine


class _SessionState(local):
    """Thread-local session holder tracking the active engine and nesting."""

    def __init__(self) -> None:
        super().__init__()
        self.engine: Optional[DatabaseEngine] = None
        self.depth: int = 0


_STATE = _SessionState()


def get_current_engine() -> Optional[DatabaseEngine]:
    """Return the active session-bound :class:`DatabaseEngine`, if any."""

    engine = _STATE.engine
    if engine is None:
        return None
    try:
        engine.reconnect()
    except Exception:
        # Drop unusable engine so callers can establish a fresh session.
        close_engine()
        return None
    return engine


def close_engine() -> None:
    """Close and clear the session-bound engine."""

    engine = _STATE.engine
    if engine is None:
        return
    try:
        engine.close()
    finally:
        _STATE.engine = None
        _STATE.depth = 0


@contextmanager
def database_session(*, reuse_connection: bool = True) -> Iterator[DatabaseEngine]:
    """Context manager that shares a :class:`DatabaseEngine` within a thread.

    When ``reuse_connection`` is ``True`` (the default), nested calls reuse the
    same engine and only close it when the outermost context exits. Setting it
    to ``False`` forces a brand new connection for the lifetime of the context.
    """

    engine = get_current_engine() if reuse_connection else None
    created = False

    if engine is None:
        engine = DatabaseEngine()
        _STATE.engine = engine
        created = True

    _STATE.depth += 1
    try:
        yield engine
    finally:
        _STATE.depth -= 1
        if created or _STATE.depth <= 0:
            close_engine()


__all__ = ["database_session", "get_current_engine", "close_engine"]

