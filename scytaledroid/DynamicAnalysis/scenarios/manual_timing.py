"""Shared timing/render helpers for manual dynamic scenario execution."""

from __future__ import annotations

import sys

from scytaledroid.Utils.DisplayUtils.colors.ansi import (
    CR,
    CURSOR_DOWN_ONE_LINE,
    CURSOR_UP_ONE_LINE,
    RESTORE_CURSOR,
    SAVE_CURSOR,
)


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


def rewrite_previous_line_preserving_prompt(message: str, *, line_width: int) -> None:
    sys.stdout.write(SAVE_CURSOR)
    sys.stdout.write(CURSOR_UP_ONE_LINE + CR)
    sys.stdout.write((" " * int(line_width)) + CR)
    sys.stdout.write(str(message).ljust(int(line_width)))
    sys.stdout.write(RESTORE_CURSOR)
    sys.stdout.flush()


def clear_prompt_and_previous_line(*, line_width: int, prompt_width: int) -> None:
    sys.stdout.write(CR + (" " * int(prompt_width)) + CR)
    sys.stdout.write(CURSOR_UP_ONE_LINE + CR + (" " * int(line_width)) + CR)
    sys.stdout.write(CURSOR_DOWN_ONE_LINE + CR)
    sys.stdout.flush()


def countdown_action_prompt_line() -> str:
    return "Enter = stop & finalize | A + Enter = abort & discard | Ctrl+C = emergency abort \u203a "


def parse_timing_action(raw: str | None) -> str:
    token = str(raw or "").strip().lower()
    if token == "":
        return "enter"
    if token in {"d", "done", "continue", "next"}:
        return "enter"
    if token in {"l", "limited", "block", "blocked"}:
        return "limited"
    if token in {"s", "stop"}:
        return "stop"
    if token in {"a", "abort"}:
        return "abort"
    if token in {"n", "skip", "notfound", "not_found"}:
        return "skip"
    if token in {"h", "home", "reset", "return_home"}:
        return "return_home"
    return "other"


__all__ = [
    "clear_status_line",
    "clear_prompt_and_previous_line",
    "countdown_action_prompt_line",
    "format_duration",
    "format_duration_precise",
    "parse_timing_action",
    "pulse_marker",
    "rewrite_previous_line_preserving_prompt",
]
