"""status_messages.py - Standardised status/info lines for CLI output."""

from __future__ import annotations

from . import colors
from .terminal import use_ascii_ui

_STATUS_PREFIX = {
    "info": "[INFO]",
    "warn": "[WARN]",
    "error": "[ERROR]",
    "success": "[OK]",
    "progress": "[RUN]",
}

_STATUS_ICONS = {
    "info": "ℹ",
    "warn": "⚠",
    "error": "✖",
    "success": "✔",
    "progress": "▶",
}

_STATUS_ICONS_ASCII = {
    "info": "i",
    "warn": "!",
    "error": "x",
    "success": "*",
    "progress": ">",
}

_STATUS_STYLES = {
    "info": ("info", "text"),
    "warn": ("warning", "warning"),
    "error": ("error", "error"),
    "success": ("success", "success"),
    "progress": ("progress", "text"),
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


def highlight(message: str, *, show_icon: bool = False) -> str:
    """Return a highlighted ribbon message."""

    styled = colors.apply(message, colors.style("highlight"), bold=True)
    if show_icon:
        icon = "★" if not use_ascii_ui() else "*"
        icon_token = colors.apply(icon, colors.style("highlight"), bold=True)
        return f"{icon_token} {styled}"
    return styled


def step(
    message: str,
    *,
    label: str | None = None,
    state: str = "progress",
    indent: int = 0,
    progress: tuple[int, int] | None = None,
    show_icon: bool = True,
) -> str:
    """Render a progress-style status line with optional label and counter."""

    prefix_tokens: list[str] = []
    if progress:
        current, total = progress
        prefix_tokens.append(_apply(f"[{current}/{total}]", "progress", bold=True))
    if label:
        prefix_tokens.append(_apply(label, "emphasis", bold=True))

    body = status(message, level=state, show_prefix=False, show_icon=show_icon)
    text = " ".join(token for token in (*prefix_tokens, body) if token)
    if indent > 0:
        text = f"{' ' * indent}{text}"
    return text


__all__ = ["print_status", "status", "step", "highlight"]
