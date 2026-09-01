"""System-level utility exports with side-effect-free package import."""

from __future__ import annotations


def utils_menu() -> None:
    """Load the interactive utility menu only when an operator invokes it."""

    from .utils_menu import utils_menu as _utils_menu

    _utils_menu()

__all__ = ["utils_menu"]
