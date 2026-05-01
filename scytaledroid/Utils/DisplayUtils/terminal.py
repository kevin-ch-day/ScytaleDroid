"""terminal.py - Helpers for querying terminal capabilities."""

from __future__ import annotations

import os
import shutil
import sys
from functools import lru_cache

from . import ui_prefs

MIN_WIDTH = 40


def _coerce_int(value: str | None, default: int) -> int:
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@lru_cache(maxsize=1)
def _determine_terminal_width(default: int) -> int:
    columns = 0
    try:
        columns = shutil.get_terminal_size().columns
    except (AttributeError, OSError):
        columns = 0

    if columns <= 0:
        columns = _coerce_int(os.environ.get("COLUMNS"), 0)

    if columns <= 0:
        columns = default

    return max(MIN_WIDTH, columns)


def get_terminal_width(*, default: int = 80, force_refresh: bool = False) -> int:
    """Return the current terminal width with sensible fallbacks."""

    if force_refresh:
        _determine_terminal_width.cache_clear()
    return _determine_terminal_width(default)


def _stdout_encoding() -> str:
    encoding = getattr(sys.stdout, "encoding", "") or ""
    if os.environ.get("PYTHONIOENCODING"):
        encoding = os.environ["PYTHONIOENCODING"]
    return encoding


def _supports_unicode() -> bool:
    encoding = _stdout_encoding()
    if not encoding:
        return False
    sample = "─⚠✔"
    try:
        sample.encode(encoding)
    except UnicodeEncodeError:
        return False
    return True


@lru_cache(maxsize=1)
def _determine_ascii_mode() -> bool:
    if os.environ.get("ASCII_UI"):
        return True
    if not ui_prefs.use_unicode():
        return True
    term = os.environ.get("TERM", "")
    if term.lower() == "dumb":
        return True
    if sys.platform.startswith("win") and not os.environ.get("WT_SESSION"):
        # Legacy Windows consoles often lack proper Unicode support
        return True
    return not _supports_unicode()


def use_ascii_ui(*, force_refresh: bool = False) -> bool:
    """Return ``True`` when UI widgets should avoid box drawing/emoji."""

    if force_refresh:
        _determine_ascii_mode.cache_clear()
    return _determine_ascii_mode()


__all__ = ["get_terminal_width", "use_ascii_ui"]
