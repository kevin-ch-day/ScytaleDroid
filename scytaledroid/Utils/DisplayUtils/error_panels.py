"""error_panels.py - Consistent panel rendering for terminal output."""

from __future__ import annotations

import textwrap
import traceback
from typing import Iterable, Optional

from . import colors
from .terminal import get_terminal_width, use_ascii_ui


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


def _wrap_line(text: str, width: int) -> list[str]:
    if width <= 0:
        return [text]
    wrapped = textwrap.wrap(
        text,
        width=width,
        break_long_words=True,
        break_on_hyphens=False,
    )
    return wrapped or [text]


def format_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: Optional[int] = None,
    tone: str = "info",
) -> str:
    """Return a coloured panel containing *message* and optional extras."""

    tone = tone if tone in _TONES else "info"
    border_style, title_style, message_style, hint_style = _resolve_styles(tone)

    term_width = get_terminal_width()
    if width is None:
        panel_width = min(80, max(40, term_width - 2))
    else:
        panel_width = min(width, term_width)
    panel_width = max(20, panel_width)
    content_width = panel_width

    ascii_ui = use_ascii_ui()
    divider_char = "-" if ascii_ui else "─"
    bullet = "- " if ascii_ui else "• "

    content: list[str] = []

    stripped_title = title.strip()
    if stripped_title:
        title_lines = _wrap_line(stripped_title.upper(), content_width)
        for line in title_lines:
            content.append(colors.apply(line, title_style, bold=True))

    message_lines = _wrap_line(message.strip(), content_width)
    for line in message_lines:
        content.append(colors.apply(line, message_style))

    for line in details or ():
        detail = line.rstrip()
        if not detail:
            continue
        wrapped_detail = _wrap_line(detail, max(10, content_width - len(bullet)))
        for index, segment in enumerate(wrapped_detail):
            prefix = bullet if index == 0 else "  "
            content.append(colors.apply(f"{prefix}{segment}", message_style))

    if hint:
        hint_lines = _wrap_line(f"Hint: {hint.strip()}", content_width)
        for line in hint_lines:
            content.append(colors.apply(line, hint_style))

    divider = colors.apply(divider_char * content_width, border_style)

    block = [divider]
    block.extend(content)
    block.append(divider)
    return "\n".join(block)


def print_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: Optional[int] = None,
    tone: str = "info",
) -> None:
    """Print a formatted panel."""

    panel = format_panel(title, message, details=details, hint=hint, width=width, tone=tone)
    print()
    print(panel)
    print()


def print_exception(
    exc: BaseException,
    *,
    context: Optional[str] = None,
    hint: Optional[str] = None,
    width: Optional[int] = None,
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
    width: Optional[int] = None,
) -> str:
    return format_panel(title, message, details=details, hint=hint, width=width, tone="error")


def print_error_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: Optional[int] = None,
) -> None:
    print_panel(title, message, details=details, hint=hint, width=width, tone="error")


def print_info_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: Optional[int] = None,
) -> None:
    print_panel(title, message, details=details, hint=hint, width=width, tone="info")


def print_warning_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: Optional[int] = None,
) -> None:
    print_panel(title, message, details=details, hint=hint, width=width, tone="warning")


def print_success_panel(
    title: str,
    message: str,
    *,
    details: Optional[Iterable[str]] = None,
    hint: Optional[str] = None,
    width: Optional[int] = None,
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
