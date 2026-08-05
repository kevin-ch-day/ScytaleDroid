"""CLI entry points for static analysis workflows."""

from __future__ import annotations

from typing import Any

__all__ = ["static_analysis_menu"]


def __getattr__(name: str) -> Any:
    """Load the interactive menu only when a caller actually requests it."""

    if name == "static_analysis_menu":
        from .menus.static_analysis_menu import static_analysis_menu

        return static_analysis_menu
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
