"""Shared SQL helper utilities for Database Utilities menus."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Sequence

from scytaledroid.Database.db_core import run_sql


def scalar(query: str, params: Sequence[Any] | None = None) -> Optional[int]:
    try:
        row = run_sql(query, params, fetch="one")
    except Exception:
        return None
    if not row:
        return None
    value = row[0]
    return int(value) if value is not None else None


def view_exists(name: str) -> bool:
    try:
        row = run_sql(
            """
            SELECT COUNT(*)
            FROM information_schema.views
            WHERE table_schema = DATABASE() AND table_name = %s
            """,
            (name,),
            fetch="one",
        )
    except Exception:
        return False
    return bool(row and row[0])


def coerce_datetime(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(candidate, fmt)
            except Exception:
                continue
        try:
            return datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def format_session_stamp(ts: Optional[datetime]) -> Optional[str]:
    if ts is None:
        return None
    return ts.strftime("%Y%m%d-%H%M%S")


__all__ = [
    "scalar",
    "view_exists",
    "coerce_datetime",
    "format_session_stamp",
]

