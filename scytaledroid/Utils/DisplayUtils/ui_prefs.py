"""ui_prefs.py - Simple, process-local UI preferences for the CLI.

This module intentionally keeps settings in-memory for the current run.
If persistence is needed later, we can extend it to read/write JSON under
``data/state/ui_prefs.json``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class _UIPrefs:
    clear_on_nav: bool = False  # default off to avoid surprising clears
    max_width: int = 100        # soft cap used by some menus


_PREFS = _UIPrefs()


def should_clear() -> bool:
    return bool(_PREFS.clear_on_nav)


def set_clear(enabled: bool) -> None:
    _PREFS.clear_on_nav = bool(enabled)


def toggle_clear() -> bool:
    _PREFS.clear_on_nav = not _PREFS.clear_on_nav
    return _PREFS.clear_on_nav


def get_max_width() -> int:
    return int(_PREFS.max_width or 100)


def set_max_width(width: int) -> int:
    try:
        w = int(width)
    except Exception:
        w = 100
    _PREFS.max_width = max(60, min(140, w))
    return _PREFS.max_width


__all__ = [
    "should_clear",
    "set_clear",
    "toggle_clear",
    "get_max_width",
    "set_max_width",
]

