"""Core definitions for credential string patterns."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from re import Pattern


@dataclass(frozen=True)
class StringPattern:
    """Represents a compiled regex and its provider metadata."""

    name: str
    description: str
    pattern: Pattern[str]
    category: str = "generic"
    provider: str | None = None
    tags: tuple[str, ...] = ()
    min_length: int = 0
    preferred_origins: tuple[str, ...] | None = None
    context_keywords: tuple[str, ...] = ()

    def iter_matches(self, value: str) -> tuple[str, ...]:
        """Return de-duplicated regex matches for *value*."""

        if not value or (self.min_length and len(value) < self.min_length):
            return tuple()

        seen: set[str] = set()
        matches: list[str] = []
        for match in self.pattern.finditer(value):
            fragment = _select_fragment(match)
            if not fragment:
                continue
            fragment = fragment.strip()
            if not fragment or (self.min_length and len(fragment) < self.min_length):
                continue
            if fragment in seen:
                continue
            seen.add(fragment)
            matches.append(fragment)
        return tuple(matches)


def _select_fragment(match: re.Match[str]) -> str:
    if match.lastindex:
        for index in range(1, match.lastindex + 1):
            candidate = match.group(index)
            if candidate:
                return candidate
    return match.group(0)


DEFAULT_ORIGINS = ("code", "resource", "asset", "raw")


def categorize_patterns(
    patterns: Iterable[StringPattern],
) -> Mapping[str, tuple[StringPattern, ...]]:
    """Organize patterns by category for quick lookups."""

    buckets: dict[str, list[StringPattern]] = {}
    for pattern in patterns:
        buckets.setdefault(pattern.category, []).append(pattern)
    return {name: tuple(sorted(bucket, key=lambda item: item.name)) for name, bucket in buckets.items()}


def lookup_pattern(name: str, *, patterns: Sequence[StringPattern]) -> StringPattern | None:
    """Return a pattern by *name* if present."""

    for pattern in patterns:
        if pattern.name == name:
            return pattern
    return None


__all__ = [
    "StringPattern",
    "DEFAULT_ORIGINS",
    "categorize_patterns",
    "lookup_pattern",
]