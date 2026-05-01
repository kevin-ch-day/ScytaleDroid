"""Shared timing/render helpers for manual dynamic scenario execution."""

from __future__ import annotations

import sys


def format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    min_label = "Min" if minutes == 1 else "Mins"
    sec_label = "Sec" if secs == 1 else "Secs"
    return f"{minutes} {min_label} {secs} {sec_label}"


def format_duration_precise(seconds: int) -> str:
    seconds = max(int(seconds), 0)
    if seconds < 60:
        return f"{seconds} sec"
    minutes, secs = divmod(seconds, 60)
    min_label = "min" if minutes == 1 else "mins"
    sec_label = "sec" if secs == 1 else "sec"
    return f"{minutes} {min_label} {secs} {sec_label} ({seconds}s)"


def pulse_marker(elapsed_seconds: int) -> str:
    if elapsed_seconds > 0 and elapsed_seconds % 10 == 0:
        return " •"
    return ""


def clear_status_line(line_width: int) -> None:
    if not sys.stdout.isatty():
        return
    sys.stdout.write("\r" + (" " * int(line_width)) + "\r")
    sys.stdout.flush()


def parse_timing_action(raw: str | None) -> str:
    token = str(raw or "").strip().lower()
    if token == "":
        return "enter"
    if token in {"d", "done", "c", "continue", "next"}:
        return "enter"
    if token in {"s", "stop"}:
        return "stop"
    if token in {"a", "abort"}:
        return "abort"
    if token in {"n", "skip", "notfound", "not_found"}:
        return "skip"
    return "other"


__all__ = [
    "clear_status_line",
    "format_duration",
    "format_duration_precise",
    "parse_timing_action",
    "pulse_marker",
]
