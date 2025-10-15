"""Renderer: end-of-run risk summaries.

Thin wrapper to make the summary entry point explicit in imports.
"""

from __future__ import annotations

from .simple import render_after_run_summary as render

__all__ = ["render"]

