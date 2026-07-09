"""Baseline helpers for static-analysis engines."""

from __future__ import annotations

from typing import Any


def __getattr__(name: str) -> Any:
    if name == "analyse_strings":
        from .strings import analyse_strings

        return analyse_strings
    raise AttributeError(name)

__all__ = ["analyse_strings"]
