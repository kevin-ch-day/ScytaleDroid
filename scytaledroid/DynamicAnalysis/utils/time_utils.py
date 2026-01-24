"""Time helpers for dynamic analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_seconds(value: Optional[int]) -> str:
    if value is None:
        return "—"
    mins, secs = divmod(int(value), 60)
    if mins:
        return f"{mins}m {secs:02d}s"
    return f"{secs}s"

