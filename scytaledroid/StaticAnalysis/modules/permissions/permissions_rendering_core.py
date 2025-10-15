"""Core permission rendering and summarization utilities.

This module consolidates functions formerly exposed via ``simple.py``.
Prefer importing from this module going forward. The legacy module remains
as a thin wrapper for backward compatibility.
"""

from __future__ import annotations

# Re-export from the legacy module to keep a single implementation.
from .simple import (
    render_permission_postcard,
    render_after_run_summary,
    render_signal_matrix,
    render_permission_matrix,
    _abbr_from_name,
)

__all__ = [
    "render_permission_postcard",
    "render_after_run_summary",
    "render_signal_matrix",
    "render_permission_matrix",
    "_abbr_from_name",
]

