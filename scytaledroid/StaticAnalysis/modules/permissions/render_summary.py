"""Legacy compatibility wrapper for end-of-run permission summaries.

Active code should prefer importing from ``permission_console_rendering``
directly. This module currently has no in-repo callers and remains only as a
compatibility alias until the wrapper-removal batch is approved.
"""

from __future__ import annotations

from .permission_console_rendering import render_after_run_summary as render

__all__ = ["render"]
