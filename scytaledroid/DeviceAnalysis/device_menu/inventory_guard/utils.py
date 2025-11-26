"""Generic helper utilities for inventory guard flows."""

from __future__ import annotations

from typing import Optional, Tuple


def humanize_seconds(seconds: float) -> str:
    """Render durations as Hh Mm Ss with consistent spacing/padding."""

    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def coarse_time_range(seconds: float) -> str:
    """Return a coarse, human-friendly time range (e.g., "~5–10 min").

    The lower bound is pessimistically rounded down; the upper bound is
    optimistically rounded up to avoid false precision.
    """

    if seconds <= 0:
        return "~seconds"
    s = int(seconds)
    if s < 60:
        lo = max(5, (s // 10) * 10)
        hi = min(60, ((s + 9) // 10) * 10)
        return f"~{lo}–{hi}s"
    minutes, _ = divmod(s, 60)
    if minutes < 10:
        lo = max(1, minutes)
        hi = min(10, minutes + 2)
        return f"~{lo}–{hi} min"
    if minutes < 60:
        lo = (minutes // 5) * 5
        hi = lo + 10
        return f"~{lo}–{hi} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 6:
        lo = hours
        hi = hours + 1
        return f"~{lo}–{hi} h"
    return "~hours"


def coerce_float(value: object) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def coerce_int(value: object) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        try:
            return int(value)
        except ValueError:
            return None
    if isinstance(value, float):
        try:
            return int(value)
        except (OverflowError, ValueError):
            return None
    return None
