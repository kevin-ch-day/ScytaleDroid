"""AI and machine learning credential patterns."""

from __future__ import annotations

import re

from .base import DEFAULT_ORIGINS, StringPattern

PATTERNS: tuple[StringPattern, ...] = (
    StringPattern(
        name="openai_api_key",
        description="Potential OpenAI API key",
        pattern=re.compile(r"sk-[A-Za-z0-9]{32,48}"),
        category="ai",
        provider="OpenAI",
        tags=("api_key", "openai"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
)

__all__ = ["PATTERNS"]