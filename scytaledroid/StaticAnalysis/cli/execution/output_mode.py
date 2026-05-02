"""Terminal output mode helpers for static analysis CLI execution."""

from __future__ import annotations

import os

_VERBOSE_VALUES = {"1", "true", "yes", "on", "verbose", "debug"}


def verbose_results_enabled() -> bool:
    """Return True when detailed terminal result output should be shown."""
    value = os.getenv("SCYTALEDROID_VERBOSE_RESULTS", "").strip().lower()
    return value in _VERBOSE_VALUES


def compact_success_output_enabled() -> bool:
    """Return True when successful runs should suppress detail-heavy terminal output."""
    return not verbose_results_enabled()