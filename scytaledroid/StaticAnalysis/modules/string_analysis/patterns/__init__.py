"""Pattern registry for string analysis detectors."""

from __future__ import annotations

from itertools import chain
from typing import Iterable, Mapping, Sequence

from .ai import PATTERNS as AI_PATTERNS
from .analytics import PATTERNS as ANALYTICS_PATTERNS
from .base import (
    DEFAULT_ORIGINS,
    StringPattern,
    categorize_patterns as _categorize_patterns,
    lookup_pattern as _lookup_pattern,
)
from .cloud import PATTERNS as CLOUD_PATTERNS
from .communications import PATTERNS as COMMUNICATION_PATTERNS
from .developer_tools import PATTERNS as DEVELOPER_PATTERNS
from .generic import PATTERNS as GENERIC_PATTERNS
from .payments import PATTERNS as PAYMENT_PATTERNS

_GROUPS: tuple[tuple[StringPattern, ...], ...] = (
    CLOUD_PATTERNS,
    PAYMENT_PATTERNS,
    COMMUNICATION_PATTERNS,
    DEVELOPER_PATTERNS,
    ANALYTICS_PATTERNS,
    AI_PATTERNS,
    GENERIC_PATTERNS,
)


def build_default_patterns() -> tuple[StringPattern, ...]:
    """Combine all registered pattern groups."""

    return tuple(chain.from_iterable(_GROUPS))


DEFAULT_PATTERNS: tuple[StringPattern, ...] = build_default_patterns()


def categorize_patterns(
    patterns: Iterable[StringPattern] | None = None,
) -> Mapping[str, tuple[StringPattern, ...]]:
    """Organize patterns by category."""

    return _categorize_patterns(patterns or DEFAULT_PATTERNS)


def lookup_pattern(
    name: str,
    *,
    patterns: Sequence[StringPattern] | None = None,
) -> StringPattern | None:
    """Return a pattern by *name* if present."""

    target = patterns if patterns is not None else DEFAULT_PATTERNS
    return _lookup_pattern(name, patterns=target)


__all__ = [
    "StringPattern",
    "DEFAULT_ORIGINS",
    "DEFAULT_PATTERNS",
    "build_default_patterns",
    "categorize_patterns",
    "lookup_pattern",
]
