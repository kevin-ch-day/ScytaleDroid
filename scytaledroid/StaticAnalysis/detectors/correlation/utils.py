"""Utility helpers shared across correlation modules."""

from __future__ import annotations

from pathlib import Path


def report_pointer(path: Path) -> str:
    """Return a stable pointer string for a stored report path."""

    return f"report://{path.name}"


__all__ = ["report_pointer"]