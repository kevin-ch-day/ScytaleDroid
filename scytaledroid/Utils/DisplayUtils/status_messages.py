"""status_messages.py - Standardised status/info lines for CLI output."""

from __future__ import annotations

from . import colors
from .terminal import use_ascii_ui

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

_STATUS_ICONS_ASCII = {
    "info": "i",
    "warn": "!",
    "error": "x",
    "success": "*",
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


def status(
    message: str,
    level: str = "info",
    *,
    show_icon: bool = True,
    show_prefix: bool = True,
) -> str:
    """Return a formatted status line."""

    prefix_text = _STATUS_PREFIX.get(level, "[INFO]")
    styles = _STATUS_STYLES.get(level, ("info", "text"))
    formatted_message = _apply(message, styles[1])
    if show_icon:
        icon = _STATUS_ICONS_ASCII.get(level) if use_ascii_ui() else _STATUS_ICONS.get(level)
    else:
        icon = None
    token_parts: list[str] = []
    if icon:
        token_parts.append(colors.apply(icon, colors.style("hint")))
    if show_prefix:
        token_parts.append(_apply(prefix_text, styles[0], bold=True))
    token_parts.append(formatted_message)
    return " ".join(part for part in token_parts if part)


def print_status(message: str, level: str = "info") -> None:
    """Print a status line immediately."""

    print(status(message, level=level))


__all__ = ["print_status", "status"]
