"""Process-local output preferences for menu-driven UI.

These preferences act as defaults for renderers and analysis modules. They are
in-memory for the current run; persistence can be added later if needed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class OutputPrefs:
    verbose: bool = False
    analytics_detail: bool = False
    string_max_samples: int = 2
    cleartext_only: bool = False


_PREFS = OutputPrefs()


def get() -> OutputPrefs:
    return _PREFS


def set_verbose(enabled: bool) -> None:
    _PREFS.verbose = bool(enabled)


def toggle_verbose() -> bool:
    _PREFS.verbose = not _PREFS.verbose
    return _PREFS.verbose


def set_analytics_detail(enabled: bool) -> None:
    _PREFS.analytics_detail = bool(enabled)


def toggle_analytics_detail() -> bool:
    _PREFS.analytics_detail = not _PREFS.analytics_detail
    return _PREFS.analytics_detail


def set_string_max_samples(value: int) -> int:
    try:
        v = int(value)
    except Exception:
        v = 2
    _PREFS.string_max_samples = max(1, min(20, v))
    return _PREFS.string_max_samples


def set_cleartext_only(enabled: bool) -> None:
    _PREFS.cleartext_only = bool(enabled)


def toggle_cleartext_only() -> bool:
    _PREFS.cleartext_only = not _PREFS.cleartext_only
    return _PREFS.cleartext_only


__all__ = [
    "get",
    "set_verbose",
    "toggle_verbose",
    "set_analytics_detail",
    "toggle_analytics_detail",
    "set_string_max_samples",
    "set_cleartext_only",
    "toggle_cleartext_only",
]

