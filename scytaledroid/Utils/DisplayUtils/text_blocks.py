"""text_blocks.py - Reusable helpers for consistent CLI text output."""

from __future__ import annotations

import re
import unicodedata
from typing import Iterable

from . import colors
from .terminal import get_terminal_width, use_ascii_ui

_DEFAULT_WIDTH = 60

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _char_display_width(char: str) -> int:
    if char == "\t":
        return 4
    if unicodedata.combining(char) or char in {"\u200c", "\u200d"}:
        return 0
    east = unicodedata.east_asian_width(char)
    return 2 if east in {"W", "F"} else 1


def _display_width(text: str) -> int:
    stripped = unicodedata.normalize("NFC", colors.strip(text))
    return sum(_char_display_width(char) for char in stripped)


def visible_width(text: str) -> int:
    """Return the printable width of *text* accounting for ANSI codes."""

    return _display_width(text)


def _ellipsis() -> str:
    return "..." if use_ascii_ui() else "…"


def truncate_visible(text: str, limit: int) -> str:
    """Trim *text* to *limit* printable characters while preserving styling."""

    if limit <= 0 or not text:
        return ""

    if _display_width(text) <= limit:
        return text

    ellipsis = _ellipsis()
    ellipsis_width = _display_width(ellipsis)
    target = max(0, limit - ellipsis_width)
    result: list[str] = []
    visible = 0
    index = 0
    length = len(text)

    while index < length and visible < target:
        char = text[index]
        if char == "\x1b":
            match = _ANSI_RE.match(text, index)
            if match:
                result.append(match.group())
                index = match.end()
                continue
        width = _char_display_width(char)
        if visible + width > target:
            break
        result.append(char)
        visible += width
        index += 1

    result.append(ellipsis)

    while index < length:
        if text[index] == "\x1b":
            match = _ANSI_RE.match(text, index)
            if match:
                result.append(match.group())
                index = match.end()
                continue
        index += 1

    return "".join(result)


def divider(char: str = "-", *, width: int | None = None, style: str | None = "divider") -> str:
    """Return a horizontal divider line optionally colourised via the palette."""

    effective_width = width if width is not None else max(0, get_terminal_width() - 2)
    line = char * max(0, effective_width)
    if style and colors.colors_enabled():
        return colors.apply(line, colors.style(style))
    return line


def boxed(lines: Iterable[str], *, width: int | None = None, padding: int = 1) -> str:
    """Return *lines* surrounded by a box with ANSI-aware layout."""

    processed = [str(line).rstrip() for line in lines]
    if not processed:
        processed = [""]

    terminal_width = width if width is not None else get_terminal_width()
    max_visible = max((_display_width(line) for line in processed), default=0)
    inner_width = min(max_visible + padding * 2, max(0, terminal_width - 2))

    ascii_ui = use_ascii_ui()
    horizontal = "-" if ascii_ui else "─"
    left_top = "+" if ascii_ui else "╭"
    right_top = "+" if ascii_ui else "╮"
    left_bottom = "+" if ascii_ui else "╰"
    right_bottom = "+" if ascii_ui else "╯"
    vertical = "|" if ascii_ui else "│"

    border_style = colors.style("divider") if colors.colors_enabled() else None
    top = f"{left_top}{horizontal * inner_width}{right_top}"
    bottom = f"{left_bottom}{horizontal * inner_width}{right_bottom}"
    if border_style:
        top = colors.apply(top, border_style)
        bottom = colors.apply(bottom, border_style)
        side = colors.apply(vertical, border_style)
    else:
        side = vertical

    content_width = max(0, inner_width - padding * 2)
    lines_out: list[str] = [top]
    for line in processed:
        truncated = truncate_visible(line, content_width)
        visible = _display_width(truncated)
        left_pad = " " * padding
        remaining = inner_width - (padding + visible + padding)
        right_padding = padding + max(0, remaining)
        padded = f"{left_pad}{truncated}{' ' * right_padding}"
        lines_out.append(f"{side}{padded}{side}")
    lines_out.append(bottom)

    return "\n".join(lines_out)


def headline(title: str, *, width: int | None = None, style: str = "header") -> str:
    """Return a styled headline followed by a thin divider."""

    available_width = width if width is not None else get_terminal_width()
    title = title.strip()
    visible = _display_width(title)
    underline_width = max(0, visible if visible else available_width)
    underline_width = min(underline_width, available_width)
    if colors.colors_enabled():
        styled_title = colors.apply(title, colors.style(style), bold=True)
    else:
        styled_title = title
    underline = divider("─" if not use_ascii_ui() else "-", width=underline_width, style="divider")
    return f"{styled_title}\n{underline}"


def bullet_list(items: Iterable[str], *, bullet: str | None = None) -> str:
    """Return a formatted bullet list."""

    ascii_ui = use_ascii_ui()
    marker = bullet if bullet is not None else ("- " if ascii_ui else "• ")
    return "\n".join(f"{marker}{item}" for item in items)


__all__ = [
    "boxed",
    "bullet_list",
    "divider",
    "headline",
    "truncate_visible",
    "visible_width",
]
