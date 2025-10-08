"""Utility helpers for string indexing."""

from __future__ import annotations

import re
from typing import Iterable, Pattern

_PRINTABLE_FRAGMENT = re.compile(r"[\x20-\x7e]{4,}")


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


def strings_from_text(blob: bytes) -> tuple[str, ...]:
    """Return candidate UTF-8 strings from a textual *blob*."""

    text = blob.decode("utf-8", errors="ignore")
    if not text:
        return tuple()

    seen: set[str] = set()
    results: list[str] = []

    for match in _PRINTABLE_FRAGMENT.finditer(text):
        candidate = match.group(0).strip()
        if len(candidate) < 4:
            continue
        if len(candidate) > 2048:
            results.extend(_dedupe_chunks(_split_long_fragment(candidate), seen))
            continue
        if candidate not in seen:
            seen.add(candidate)
            results.append(candidate)

    return tuple(results)


def strings_from_binary(blob: bytes) -> tuple[str, ...]:
    """Return printable ASCII fragments from a binary *blob*."""

    if not blob:
        return tuple()

    try:
        text = blob.decode("utf-8", errors="ignore")
    except Exception:  # pragma: no cover - defensive
        return tuple()

    seen: set[str] = set()
    results: list[str] = []

    for match in _PRINTABLE_FRAGMENT.finditer(text):
        candidate = match.group(0).strip()
        if len(candidate) < 6:
            continue
        if candidate not in seen:
            seen.add(candidate)
            results.append(candidate)

    return tuple(results)


def _dedupe_chunks(chunks: Iterable[str], seen: set[str]) -> Iterable[str]:
    for chunk in chunks:
        if chunk not in seen:
            seen.add(chunk)
            yield chunk


def _split_long_fragment(value: str) -> Iterable[str]:
    chunks: list[str] = []
    for piece in value.splitlines():
        piece = piece.strip()
        if not piece:
            continue
        if len(piece) > 2048:
            chunks.extend(_split_even_chunks(piece, 2048))
        else:
            chunks.append(piece)
    if not chunks:
        if len(value) > 2048:
            chunks.extend(_split_even_chunks(value, 2048))
        else:
            chunks.append(value)
    return tuple(chunks)


def _split_even_chunks(value: str, size: int) -> Iterable[str]:
    return tuple(
        value[i : i + size]
        for i in range(0, len(value), size)
        if value[i : i + size]
    )


__all__ = [
    "ensure_pattern",
    "looks_textual",
    "strings_from_text",
    "strings_from_binary",
]
