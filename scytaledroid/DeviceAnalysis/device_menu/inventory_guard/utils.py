"""Generic helper utilities for inventory guard flows."""

from __future__ import annotations


def humanize_seconds(seconds: float) -> str:
    """Render durations with explicit labels (Days Hrs Mins)."""

    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} Secs"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} Mins {sec:02d} Secs"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours} Hrs {minutes:02d} Mins"
    days, hours = divmod(hours, 24)
    return f"{days} Days {hours:02d} Hrs {minutes:02d} Mins"


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


def coerce_float(value: object) -> float | None:
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


def coerce_int(value: object) -> int | None:
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