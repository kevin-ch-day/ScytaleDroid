"""Formatting helpers for harvest summary rendering."""

from __future__ import annotations

from collections.abc import Sequence


def compact_label(label: str) -> str:
    return " ".join(label.strip().split())


def format_card_line(label: str, value: str, breakdown: Sequence[str | None] = ()) -> str:
    detail = ", ".join(part for part in breakdown if part)
    if detail:
        return f"{compact_label(label)}: {value} ({detail})"
    return f"{compact_label(label)}: {value}"


def count_phrase(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"
