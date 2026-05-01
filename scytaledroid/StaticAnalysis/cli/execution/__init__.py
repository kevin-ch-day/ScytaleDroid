"""Execution helpers for static analysis CLI flows."""

from __future__ import annotations

from .logging_setup import configure_logging_for_cli
from .permission_flow import execute_permission_scan
from .scan_flow import build_analysis_config, execute_scan, generate_report, request_abort
from .scan_formatters import format_duration


def render_run_results(*args, **kwargs):
    """Lazy wrapper to avoid importing heavy result/report modules at package import time."""
    from .results import render_run_results as _render_run_results

    return _render_run_results(*args, **kwargs)


__all__ = [
    "configure_logging_for_cli",
    "execute_permission_scan",
    "render_run_results",
    "format_duration",
    "execute_scan",
    "generate_report",
    "build_analysis_config",
    "request_abort",
]