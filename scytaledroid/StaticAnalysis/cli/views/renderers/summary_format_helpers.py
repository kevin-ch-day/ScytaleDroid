"""Small formatting helpers for static analysis summary rendering."""

from __future__ import annotations


def short_number(value: int) -> str:
    magnitude = abs(int(value))
    if magnitude >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if magnitude >= 1_000:
        return f"{value / 1_000:.1f}k"
    return str(value)


def preview_text(value: object, *, limit: int = 70) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"
