"""status_messages.py - Standardised status/info lines for CLI output."""

from __future__ import annotations

from . import colors

_STATUS_PREFIX = {
    "info": "[INFO]",
    "warn": "[WARN]",
    "error": "[ERROR]",
    "success": "[OK]",
}

_STATUS_ICONS = {
    "info": "ℹ",
    "warn": "⚠",
    "error": "✖",
    "success": "✔",
}

_STATUS_STYLES = {
    "info": ("info", "text"),
    "warn": ("warning", "warning"),
    "error": ("error", "error"),
    "success": ("success", "success"),
}


def _style_for(name: str) -> tuple[str, ...]:
    palette = colors.get_palette()
    return getattr(palette, name)


def _apply(text: str, style_name: str, *, bold: bool = False) -> str:
    return colors.apply(text, _style_for(style_name), bold=bold)


def status(message: str, level: str = "info", *, show_icon: bool = True) -> str:
    """Return a formatted status line."""

    prefix_text = _STATUS_PREFIX.get(level, "[INFO]")
    styles = _STATUS_STYLES.get(level, ("info", "text"))
    prefix = _apply(prefix_text, styles[0], bold=True)
    formatted_message = _apply(message, styles[1])
    icon = _STATUS_ICONS.get(level) if show_icon else None
    if icon:
        icon_text = colors.apply(icon, colors.style("hint"))
        return f"{icon_text} {prefix} {formatted_message}"
    return f"{prefix} {formatted_message}"


def print_status(message: str, level: str = "info") -> None:
    """Print a status line immediately."""

    print(status(message, level=level))


__all__ = ["print_status", "status"]
