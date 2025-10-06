"""error_panels.py - Consistent panel rendering for terminal output."""

from __future__ import annotations

import traceback
from typing import Iterable, Optional

from . import colors, text_blocks


_TONES = ("info", "warning", "success", "error")


def _resolve_styles(tone: str) -> tuple:
    palette = colors.get_palette()
    mapping = {
        "error": (
            palette.error_panel_border,
            palette.error_panel_title,
            palette.error_panel_message,
            palette.error_panel_hint,
        ),
        "info": (
            palette.info_panel_border,
            palette.info_panel_title,
            palette.info_panel_message,
            palette.info_panel_hint,
        ),
        "warning": (
            palette.warning_panel_border,
            palette.warning_panel_title,
            palette.warning_panel_message,
            palette.warning_panel_hint,
        ),
        "success": (
            palette.success_panel_border,
            palette.success_panel_title,
            palette.success_panel_message,
            palette.success_panel_hint,
        ),
    }
    return mapping.get(tone, mapping["error"])


def _style_box(lines: list[str], kinds: list[str], tone: str) -> str:
    border_style, title_style, message_style, hint_style = _resolve_styles(tone)
    styled: list[str] = []
    last_index = len(lines) - 1
    for idx, line in enumerate(lines):
        if idx == 0 or idx == last_index:
            styled.append(colors.apply(line, border_style))
            continue
        prefix = colors.apply(line[:2], border_style)
        suffix = colors.apply(line[-2:], border_style)
        inner = line[2:-2]
        kind = kinds[idx - 1]
        if kind == "title":
            content = colors.apply(inner, title_style, bold=True)
        elif kind == "hint":
            content = colors.apply(inner, hint_style)
        else:
            content = colors.apply(inner, message_style)
        styled.append(f"{prefix}{content}{suffix}")
    return "\n".join(styled)


def format_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: int = 72,
    tone: str = "info",
) -> str:
    """Return a coloured panel containing *message* and optional extras."""

    tone = tone if tone in _TONES else "info"

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
    return _style_box(box_lines, kinds, tone)


def print_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: int = 72,
    tone: str = "info",
) -> None:
    """Print a formatted panel."""

    print(format_panel(title, message, details=details, hint=hint, width=width, tone=tone))


def print_exception(
    exc: BaseException,
    *,
    context: Optional[str] = None,
    hint: Optional[str] = None,
    width: int = 72,
) -> None:
    """Render an exception using the standard error tone."""

    title = context or exc.__class__.__name__
    message = str(exc) or "An unexpected error occurred."
    trace_lines = [line.rstrip() for line in traceback.format_exception(exc)]
    print_panel(title, message, details=trace_lines, hint=hint, width=width, tone="error")


def format_error_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: int = 72,
) -> str:
    return format_panel(title, message, details=details, hint=hint, width=width, tone="error")


def print_error_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: int = 72,
) -> None:
    print_panel(title, message, details=details, hint=hint, width=width, tone="error")


def print_info_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: int = 72,
) -> None:
    print_panel(title, message, details=details, hint=hint, width=width, tone="info")


def print_warning_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: int = 72,
) -> None:
    print_panel(title, message, details=details, hint=hint, width=width, tone="warning")


def print_success_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: int = 72,
) -> None:
    print_panel(title, message, details=details, hint=hint, width=width, tone="success")


__all__ = [
    "format_panel",
    "print_panel",
    "print_exception",
    "format_error_panel",
    "print_error_panel",
    "print_info_panel",
    "print_warning_panel",
    "print_success_panel",
]
