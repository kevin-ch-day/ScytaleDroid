"""Session helpers for static analysis workflows."""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import re
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


SESSION_STAMP_MAX_LEN = 128


def normalize_session_stamp(label: str, *, max_len: int = SESSION_STAMP_MAX_LEN) -> str:
    """Normalize a session label for safe cross-table use while remaining unique."""
    if not label:
        return label
    cleaned = re.sub(r"[^A-Za-z0-9._:-]+", "-", label).strip("-")
    if not cleaned:
        cleaned = label
    if len(cleaned) <= max_len and cleaned != label:
        return cleaned
    if len(cleaned) <= max_len:
        return cleaned
    tail = cleaned[-15:]
    if len(tail) == 15 and tail[:8].isdigit() and tail[8] == "-" and tail[9:].isdigit():
        prefix_len = max_len - (len(tail) + 1)
        prefix = cleaned[: max(prefix_len, 0)]
        return f"{prefix}-{tail}" if prefix else tail
    digest = hashlib.sha1(cleaned.encode("utf-8")).hexdigest()[:8]
    prefix_len = max_len - (len(digest) + 1)
    prefix = cleaned[: max(prefix_len, 0)]
    return f"{prefix}-{digest}" if prefix else digest


__all__ = ["make_session_stamp", "normalize_session_stamp"]
