"""status_messages.py - Standardised status/info lines for CLI output."""

from __future__ import annotations

from collections.abc import Iterable

from . import colors, text_blocks
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
    "delta_new": ("success", "success"),
    "delta_removed": ("error", "error"),
    "delta_updated": ("warning", "warning"),
    "evidence": ("accent", "highlight"),
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


def status_delta(kind: str, value: object) -> str:
    """Return a delta-styled status ribbon (NEW/REMOVED/UPDATED)."""

    normalised = kind.lower().strip()
    level = f"delta_{normalised}"
    if level not in _STATUS_STYLES:
        level = "info"
    return status(str(value), level=level, show_icon=False)


def status_evidence(message: str) -> str:
    """Return an evidence-styled status ribbon."""

    return status(message, level="evidence", show_icon=False)


def _strip_value_style(label: str, value: object) -> tuple[str, ...] | None:
    palette = colors.get_palette()
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    key = label.strip().lower()
    norm = raw.lower()
    if key in {"status", "adb", "root"}:
        if "connected" in norm or "fresh" in norm or norm in {"ok", "pass"}:
            return palette.success
        if "stale" in norm or "warn" in norm:
            return palette.warning
        if "disconnected" in norm or "fail" in norm or "error" in norm:
            return palette.error
    if key in {"mode"} and norm:
        return palette.accent
    return None


def format_strip(
    title: str,
    items: Iterable[tuple[str, object]] = (),
    *,
    width: int | None = None,
) -> str:
    """Return a minimal status strip (title + divider + key/value lines)."""

    heading = title.strip()
    if not heading:
        return ""
    palette = colors.get_palette()
    use_color = colors.colors_enabled()
    divider = text_blocks.divider("─", width=width, style="divider")
    title_text = colors.apply(heading, palette.header, bold=True) if use_color else heading

    max_label = max((len(str(label)) for label, _ in items), default=0)
    lines: list[str] = [title_text, divider]
    for label, value in items:
        label_text = f"{str(label):<{max_label}}"
        value_text = str(value)
        if use_color:
            label_text = colors.apply(label_text, palette.muted)
            value_style = _strip_value_style(str(label), value)
            if value_style and not colors.has_ansi(value_text):
                value_text = colors.apply(value_text, value_style, bold=True)
            elif not colors.has_ansi(value_text):
                value_text = colors.apply(value_text, palette.text)
        lines.append(f"{label_text} : {value_text}")
    return "\n".join(lines)


def print_strip(
    title: str,
    items: Iterable[tuple[str, object]] = (),
    *,
    width: int | None = None,
) -> None:
    """Print a minimal status strip."""

    strip = format_strip(title, items, width=width)
    if strip:
        print(strip)


__all__ = ["format_strip", "print_status", "print_strip", "status", "step", "highlight"]
