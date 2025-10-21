"""Central placeholder token definitions used across string analysis."""

from __future__ import annotations

_PLACEHOLDERS = {
    "%s",
    "%1$s",
    "<host>",
    "<url>",
    "0.1",
    "webaddress.elided",
    "localhost",
    "example.com",
    "h",
    "dev",
    "test",
}


def is_placeholder_token(value: str | None) -> bool:
    if not value:
        return False
    return value.strip().lower() in _PLACEHOLDERS


PLACEHOLDER_TOKENS = frozenset(_PLACEHOLDERS)

__all__ = ["PLACEHOLDER_TOKENS", "is_placeholder_token"]
