"""Session helpers for static analysis workflows."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from threading import Lock

_SESSION_LOCK = Lock()
_LAST_SESSION_LABEL: str | None = None


def make_session_stamp(now: datetime | None = None) -> str:
    """Return a session stamp string.

    Session stamps use ``YYYYMMDD`` format by default. They are intended to be
    human-friendly and stable for a given day; callers may override labels if
    they need per-run uniqueness.
    """

    global _LAST_SESSION_LABEL

    candidate = now or datetime.now()
    with _SESSION_LOCK:
        stamp = candidate.strftime("%Y%m%d")
        _LAST_SESSION_LABEL = stamp
        return stamp


SESSION_STAMP_MAX_LEN = 64


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
