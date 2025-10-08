"""Presentation helpers for static analysis artefacts."""

from .view import build_report_view
from .html import render_html_report, save_html_report

__all__ = [
    "build_report_view",
    "render_html_report",
    "save_html_report",
]

