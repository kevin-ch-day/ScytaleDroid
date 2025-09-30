"""status_messages.py - Standardised status/info lines for CLI output."""

from __future__ import annotations

_STATUS_PREFIX = {
    "info": "[INFO]",
    "warn": "[WARN]",
    "error": "[ERROR]",
    "success": "[OK]",
}


def status(message: str, level: str = "info") -> str:
    """Return a formatted status line."""
    prefix = _STATUS_PREFIX.get(level, "[INFO]")
    return f"{prefix} {message}"


def print_status(message: str, level: str = "info") -> None:
    """Print a status line immediately."""
    print(status(message, level=level))
