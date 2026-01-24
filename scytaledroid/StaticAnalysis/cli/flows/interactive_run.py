"""Command-line runner for static analysis menu."""

from __future__ import annotations

from ..menus.static_analysis_menu import static_analysis_menu


def run() -> None:
    """Launch the interactive static-analysis menu."""

    static_analysis_menu()


__all__ = ["run"]
