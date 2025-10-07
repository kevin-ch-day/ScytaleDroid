"""Provider-specific string matching patterns (placeholder module)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Pattern
import re


@dataclass(frozen=True)
class StringPattern:
    """Represents a compiled regex and its provider metadata."""

    name: str
    description: str
    pattern: Pattern[str]


DEFAULT_PATTERNS: tuple[StringPattern, ...] = (
    StringPattern(
        name="google_api_key",
        description="Potential Google API key",
        pattern=re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    ),
    StringPattern(
        name="aws_access_key",
        description="Potential AWS access key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
)


__all__ = ["StringPattern", "DEFAULT_PATTERNS"]
