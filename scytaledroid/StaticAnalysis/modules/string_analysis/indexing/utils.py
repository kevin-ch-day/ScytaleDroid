"""Utility helpers for string indexing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Pattern, Tuple

_PRINTABLE_FRAGMENT = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")
_WHITESPACE = frozenset(b" \t\r\n")


@dataclass(frozen=True)
class StringFragment:
    """Represents a decoded string fragment and its byte span."""

    value: str
    start: int
    end: int

    def context(self, blob: bytes, *, radius: int = 20) -> str:
        """Return a decoded context window around this fragment."""

        head = max(self.start - radius, 0)
        tail = min(self.end + radius, len(blob))
        window = blob[head:tail]
        text = window.decode("utf-8", errors="ignore")
        if head > 0:
            text = "…" + text
        if tail < len(blob):
            text = text + "…"
        return text


def ensure_pattern(pattern: Pattern[str] | str) -> Pattern[str]:
    """Return a compiled regex for *pattern*."""

    if isinstance(pattern, str):
        return re.compile(pattern)
    return pattern


def looks_textual(blob: bytes, *, sample_size: int = 4096) -> bool:
    """Best-effort heuristic to determine if *blob* appears textual."""

    if not blob:
        return False
    sample = blob[:sample_size]
    printable = sum(1 for byte in sample if 32 <= byte <= 126 or byte in {9, 10, 13})
    ratio = printable / max(1, len(sample))
    return ratio >= 0.55


def strings_from_text(blob: bytes) -> tuple[StringFragment, ...]:
    """Return candidate string fragments from a textual *blob*."""

    return _extract_fragments(blob, minimum=4)


def strings_from_binary(blob: bytes) -> tuple[StringFragment, ...]:
    """Return printable fragments from a binary *blob*."""

    return _extract_fragments(blob, minimum=6)


def _extract_fragments(blob: bytes, *, minimum: int) -> tuple[StringFragment, ...]:
    if not blob:
        return tuple()

    results: list[StringFragment] = []
    seen: set[Tuple[int, int]] = set()

    for match in _PRINTABLE_FRAGMENT.finditer(blob):
        start, end = match.span()
        segment = bytearray(match.group(0))
        left = 0
        right = len(segment)
        while left < right and segment[left] in _WHITESPACE:
            left += 1
        while right > left and segment[right - 1] in _WHITESPACE:
            right -= 1
        if right - left < minimum:
            continue
        trimmed_start = start + left
        trimmed_end = start + right
        if (trimmed_start, trimmed_end) in seen:
            continue
        seen.add((trimmed_start, trimmed_end))
        fragment = segment[left:right]
        if len(fragment) > 4096:
            fragment = fragment[:4096]
            trimmed_end = trimmed_start + len(fragment)
        text = fragment.decode("utf-8", errors="ignore")
        if not text.strip():
            continue
        results.append(StringFragment(value=text, start=trimmed_start, end=trimmed_end))

    return tuple(results)


__all__ = [
    "ensure_pattern",
    "looks_textual",
    "strings_from_text",
    "strings_from_binary",
    "StringFragment",
]
