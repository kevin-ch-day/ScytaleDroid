"""error_panels.py - Consistent error panel rendering for terminal output."""

from __future__ import annotations

import traceback
from typing import Iterable, Optional

from . import colors, text_blocks


def _style_box(lines: list[str], kinds: list[str]) -> str:
    palette = colors.get_palette()
    styled: list[str] = []
    last_index = len(lines) - 1
    for idx, line in enumerate(lines):
        if idx == 0 or idx == last_index:
            styled.append(colors.apply(line, palette.error_panel_border))
            continue
        prefix = colors.apply(line[:2], palette.error_panel_border)
        suffix = colors.apply(line[-2:], palette.error_panel_border)
        inner = line[2:-2]
        kind = kinds[idx - 1]
        if kind == "title":
            content = colors.apply(inner, palette.error_panel_title, bold=True)
        elif kind == "hint":
            content = colors.apply(inner, palette.error_panel_hint)
        else:
            content = colors.apply(inner, palette.error_panel_message)
        styled.append(f"{prefix}{content}{suffix}")
    return "\n".join(styled)


def format_error_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: int = 72,
) -> str:
    """Return a coloured error panel containing *message* and optional extras."""

    content_lines: list[str] = []
    kinds: list[str] = []

    stripped_title = title.strip()
    if stripped_title:
        content_lines.append(stripped_title.upper())
        kinds.append("title")

    content_lines.append(message.strip())
    kinds.append("message")

    for line in details or ():
        content_lines.append(line.rstrip())
        kinds.append("detail")

    if hint:
        content_lines.append(f"Hint: {hint.strip()}")
        kinds.append("hint")

    boxed = text_blocks.boxed(content_lines, width=width)
    box_lines = boxed.splitlines()
    return _style_box(box_lines, kinds)


def print_error_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: int = 72,
) -> None:
    """Print a formatted error panel."""

    print(format_error_panel(title, message, details=details, hint=hint, width=width))


def print_exception(
    exc: BaseException,
    *,
    context: Optional[str] = None,
    hint: Optional[str] = None,
    width: int = 72,
) -> None:
    """Render an exception using the standard error panel layout."""

    title = context or exc.__class__.__name__
    message = str(exc) or "An unexpected error occurred."
    trace_lines = [line.rstrip() for line in traceback.format_exception(exc)]
    print_error_panel(title, message, details=trace_lines, hint=hint, width=width)


__all__ = [
    "format_error_panel",
    "print_error_panel",
    "print_exception",
]
