"""Renderers: signal and permission matrices.

Thin wrappers around the legacy ``simple`` module to improve discoverability.
"""

from __future__ import annotations

from .permission_console_rendering import render_signal_matrix as render_signals
from .permission_console_rendering import render_permission_matrix as render_permissions

__all__ = ["render_signals", "render_permissions"]
