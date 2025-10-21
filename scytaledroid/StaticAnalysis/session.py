"""Session helpers for static analysis workflows."""

from __future__ import annotations

from datetime import datetime, timedelta
from threading import Lock


_SESSION_LOCK = Lock()
_LAST_SESSION_TS: datetime | None = None
_LAST_SESSION_LABEL: str | None = None


def make_session_stamp(now: datetime | None = None) -> str:
    """Return a monotonic session stamp string.

    Session stamps use ``YYYYMMDD-HHMMSS`` format and are guaranteed to be
    strictly increasing for calls within the same process to avoid accidental
    reuse when runs start within the same second.
    """

    global _LAST_SESSION_TS, _LAST_SESSION_LABEL

    candidate = now or datetime.now()
    with _SESSION_LOCK:
        if _LAST_SESSION_TS and candidate <= _LAST_SESSION_TS:
            candidate = _LAST_SESSION_TS + timedelta(seconds=1)
        stamp = candidate.strftime("%Y%m%d-%H%M%S")
        if _LAST_SESSION_LABEL and stamp == _LAST_SESSION_LABEL:
            candidate = candidate + timedelta(seconds=1)
            stamp = candidate.strftime("%Y%m%d-%H%M%S")
        _LAST_SESSION_TS = candidate
        _LAST_SESSION_LABEL = stamp
        return stamp


__all__ = ["make_session_stamp"]
