"""text_blocks.py - Reusable helpers for consistent CLI text output."""

from __future__ import annotations

import re

from typing import Iterable

from . import colors

DEFAULT_WIDTH = 60

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _visible_length(text: str) -> int:
    """Return the printable width of *text* after stripping ANSI codes."""

    return len(colors.strip(text))


def _truncate_visible(text: str, limit: int) -> str:
    """Trim *text* to *limit* printable characters while preserving styling."""

    if limit <= 0 or not text:
        return ""

    if _visible_length(text) <= limit:
        return text

    target = max(0, limit - 1)
    result: list[str] = []
    visible = 0
    index = 0
    length = len(text)

    while index < length and visible < target:
        if text[index] == "\x1b":
            match = _ANSI_RE.match(text, index)
            if match:
                result.append(match.group())
                index = match.end()
                continue
        result.append(text[index])
        visible += 1
        index += 1

    result.append("…")

    while index < length:
        if text[index] == "\x1b":
            match = _ANSI_RE.match(text, index)
            if match:
                result.append(match.group())
                index = match.end()
                continue
        index += 1

    return "".join(result)


def divider(
    char: str = "-", *, width: int = DEFAULT_WIDTH, style: str | None = "divider"
) -> str:
    """Return a horizontal divider line optionally colourised via the palette."""

    line = char * max(0, width)
    if style and colors.colors_enabled():
        return colors.apply(line, colors.style(style))
    return line


def boxed(
    lines: Iterable[str], *, width: int = DEFAULT_WIDTH, padding: int = 1
) -> str:
    """Return *lines* surrounded by a rounded box with ANSI-aware layout."""

    processed = [str(line).rstrip() for line in lines]
    if not processed:
        processed = [""]

    max_visible = max((_visible_length(line) for line in processed), default=0)
    inner_width = min(max_visible + padding * 2, max(0, width - 2))

    border_style = colors.style("divider") if colors.colors_enabled() else None
    top = f"╭{'─' * inner_width}╮"
    bottom = f"╰{'─' * inner_width}╯"
    if border_style:
        top = colors.apply(top, border_style)
        bottom = colors.apply(bottom, border_style)
        side = colors.apply("│", border_style)
    else:
        side = "│"

    content_width = max(0, inner_width - padding * 2)
    lines_out: list[str] = [top]
    for line in processed:
        truncated = _truncate_visible(line, content_width)
        visible = _visible_length(truncated)
        base_padding = " " * padding
        remaining = inner_width - (padding + visible + padding)
        right_padding = padding + max(0, remaining)
        padded = f"{base_padding}{truncated}{' ' * right_padding}"
        lines_out.append(f"{side}{padded}{side}")
    lines_out.append(bottom)

    return "\n".join(lines_out)


def headline(
    title: str, *, width: int = DEFAULT_WIDTH, style: str = "header"
) -> str:
    """Return a styled headline followed by an accent divider."""

    title = title.strip()
    visible = _visible_length(title)
    underline_width = max(0, min(visible if visible else width, width))
    if colors.colors_enabled():
        styled_title = colors.apply(title, colors.style(style), bold=True)
    else:
        styled_title = title
    underline = divider("=", width=underline_width, style="divider")
    return f"{styled_title}\n{underline}"


def bullet_list(items: Iterable[str], *, bullet: str = "- ") -> str:
    """Return a formatted bullet list."""

    return "\n".join(f"{bullet}{item}" for item in items)
