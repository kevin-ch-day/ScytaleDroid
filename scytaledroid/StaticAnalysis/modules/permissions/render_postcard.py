"""Renderer: permission-first postcard view.

Thin wrapper around the legacy ``simple`` module to make intent obvious.
Prefer importing from this module in new code.
"""

from __future__ import annotations

from .simple import render_permission_postcard as render

__all__ = ["render"]

