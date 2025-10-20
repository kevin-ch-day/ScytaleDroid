"""Reusable summary cards for CLI contexts."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence as SequenceABC
from dataclasses import dataclass
from typing import Sequence, Tuple

from . import colors
from .terminal import get_terminal_width, use_ascii_ui
from .text_blocks import boxed


@dataclass(frozen=True)
class SummaryCardItem:
    """Represents a single labelled entry in a summary card."""

    label: str
    value: object
    label_style: Sequence[str] | str | None = None
    value_style: Sequence[str] | str | None = None
    bullet: str | None = None


def summary_item(
    label: str,
    value: object,
    *,
    label_style: Sequence[str] | str | None = None,
    value_style: Sequence[str] | str | None = None,
    bullet: str | None = None,
) -> SummaryCardItem:
    """Convenience helper to build a :class:`SummaryCardItem`."""

    return SummaryCardItem(str(label), value, label_style=label_style, value_style=value_style, bullet=bullet)


def _style(name: str, fallback: str) -> tuple[str, ...]:
    codes = colors.style(name)
    if codes:
        return codes
    return colors.style(fallback)


def _resolve_style(style: Sequence[str] | str | None, fallback: tuple[str, ...]) -> tuple[str, ...]:
    if style is None:
        return fallback
    if isinstance(style, tuple):
        return style
    if isinstance(style, str):
        return colors.style(style)
    if isinstance(style, SequenceABC):
        return tuple(str(code) for code in style if code)
    raise TypeError(f"Unsupported style type: {type(style)!r}")


_SEVERITY_STYLE_MAP = {
    "critical": "severity_critical",
    "criticality": "severity_critical",
    "crit": "severity_critical",
    "p0": "severity_critical",
    "sev0": "severity_critical",
    "high": "severity_high",
    "p1": "severity_high",
    "sev1": "severity_high",
    "medium": "severity_medium",
    "med": "severity_medium",
    "p2": "severity_medium",
    "sev2": "severity_medium",
    "low": "severity_low",
    "p3": "severity_low",
    "sev3": "severity_low",
    "info": "severity_info",
    "information": "severity_info",
    "note": "severity_info",
    "notes": "severity_info",
    "p4": "severity_info",
    "sev4": "severity_info",
}


def _auto_value_style(label: str) -> tuple[str, ...] | None:
    text = re.sub(r"[^a-z0-9]+", " ", label.lower()).strip()
    if not text:
        return None
    for token in text.split():
        style_name = _SEVERITY_STYLE_MAP.get(token)
        if style_name:
            return _style(style_name, "progress")
    # Support shorthand such as "H" or "M" on bare labels.
    if len(text) == 1:
        mapping = {"c": "severity_critical", "h": "severity_high", "m": "severity_medium", "l": "severity_low", "i": "severity_info"}
        style_name = mapping.get(text)
        if style_name:
            return _style(style_name, "progress")
    return None


def _coerce_items(items: Sequence[SummaryCardItem] | Iterable[SummaryCardItem | tuple[str, object]]) -> list[SummaryCardItem]:
    coerced: list[SummaryCardItem] = []
    for entry in items:
        if isinstance(entry, SummaryCardItem):
            coerced.append(entry)
        elif isinstance(entry, tuple):
            if len(entry) != 2:
                raise ValueError("Summary card tuples must contain exactly two items")
            coerced.append(SummaryCardItem(str(entry[0]), entry[1]))
        else:
            raise TypeError(f"Unsupported summary card item type: {type(entry)!r}")
    return coerced


def format_summary_card(
    title: str,
    items: Sequence[SummaryCardItem | Tuple[str, object]]
    | Iterable[SummaryCardItem | Tuple[str, object]],
    *,
    subtitle: str | None = None,
    footer: str | None = None,
    width: int | None = None,
) -> str:
    """Return a formatted summary card highlighting key-value pairs."""

    ascii_ui = use_ascii_ui()
    bullet = "- " if ascii_ui else "• "
    max_width = width if width is not None else min(get_terminal_width(), 100)

    primary_style = _style("banner_primary", "header")
    secondary_style = _style("banner_secondary", "muted")
    value_style = _style("progress", "accent")
    footer_style = _style("hint", "muted")

    lines: list[str] = []
    title_text = colors.apply(title.strip(), primary_style, bold=True)
    lines.append(title_text)
    if subtitle:
        lines.append(colors.apply(subtitle.strip(), secondary_style))

    for entry in _coerce_items(items):
        label_tokens = _resolve_style(entry.label_style, secondary_style)
        inferred_value_style = _auto_value_style(entry.label)
        value_tokens = _resolve_style(
            entry.value_style,
            inferred_value_style if inferred_value_style is not None else value_style,
        )
        label_text = colors.apply(str(entry.label), label_tokens)
        value_text = colors.apply(str(entry.value), value_tokens, bold=True)
        bullet_token = entry.bullet if entry.bullet is not None else bullet
        prefix = bullet_token if bullet_token is not None else ""
        lines.append(f"{prefix}{label_text}: {value_text}")

    if footer:
        lines.append(colors.apply(footer, footer_style))

    return boxed(lines, width=max_width, padding=1)


def print_summary_card(
    title: str,
    items: Sequence[SummaryCardItem | Tuple[str, object]]
    | Iterable[SummaryCardItem | Tuple[str, object]],
    *,
    subtitle: str | None = None,
    footer: str | None = None,
    width: int | None = None,
) -> None:
    """Print a summary card directly to stdout."""

    print(format_summary_card(title, items, subtitle=subtitle, footer=footer, width=width))


__all__ = ["SummaryCardItem", "format_summary_card", "print_summary_card", "summary_item"]
