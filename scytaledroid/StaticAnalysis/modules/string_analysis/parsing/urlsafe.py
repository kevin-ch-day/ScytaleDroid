"""Shared URL parsing helpers.

Python 3.14 tightened ``urllib.parse.urlsplit`` and now raises ``ValueError``
for malformed bracketed hosts such as invalid IPv6 literals. Static analysis
must treat those strings as malformed evidence, not as fatal runtime errors.
"""

from __future__ import annotations

from urllib.parse import SplitResult, urlsplit


def safe_urlsplit(value: str) -> SplitResult | None:
    """Return ``urlsplit(value)`` or ``None`` when the URL is malformed."""

    try:
        return urlsplit(value)
    except ValueError:
        return None


__all__ = ["safe_urlsplit"]
