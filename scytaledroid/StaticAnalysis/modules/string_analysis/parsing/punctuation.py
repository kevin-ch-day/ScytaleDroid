"""Utilities for trimming punctuation artifacts around extracted tokens."""

from __future__ import annotations

import re

_LEADING = set("(\"'[{<")
_TRAILING = set(")\"'}]>.,;:.")
_IPV6_CANDIDATE = re.compile(r"\[[0-9A-Fa-f:.%-]+\]")


def _looks_like_ipv6_suffix(value: str) -> bool:
    """Return ``True`` when *value* ends with a bracketed IPv6 literal."""

    if "]" not in value or "[" not in value:
        return False
    close_index = value.rfind("]")
    if close_index != len(value) - 1:
        return False
    open_index = value.rfind("[", 0, close_index)
    if open_index == -1:
        return False
    candidate = value[open_index : close_index + 1]
    return bool(_IPV6_CANDIDATE.fullmatch(candidate))


def strip_wrap_punct(text: str) -> str:
    """Remove leading/trailing wrapper punctuation from *text* without harming IPv6."""

    if not text:
        return text

    stripped = text.strip()

    # Remove leading punctuation wrappers greedily.
    while stripped and stripped[0] in _LEADING:
        stripped = stripped[1:]

    # Remove trailing punctuation but keep IPv6 brackets intact.
    while stripped and stripped[-1] in _TRAILING:
        if stripped[-1] == "]" and _looks_like_ipv6_suffix(stripped):
            break
        stripped = stripped[:-1].rstrip()

    return stripped


__all__ = ["strip_wrap_punct"]
