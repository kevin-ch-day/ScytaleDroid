# File: simple.py
"""Legacy wrapper for permission console helpers."""

from __future__ import annotations

from .permission_console_rendering import (
    _abbr_from_name,
    print_permissions_block,
    render_after_run_summary,
    render_barcode_line,
    render_contribution_summary,
    render_permission_matrix,
    render_permission_postcard,
    render_scoring_legend,
    render_signal_matrix,
)
from .permission_manifest_extract import collect_permissions_and_sdk

__all__ = [
    "collect_permissions_and_sdk",
    "print_permissions_block",
    "render_permission_postcard",
    "render_after_run_summary",
    "render_signal_matrix",
    "render_permission_matrix",
    "render_barcode_line",
    "render_contribution_summary",
    "render_scoring_legend",
    "_abbr_from_name",
]