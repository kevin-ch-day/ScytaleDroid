"""Utilities for trimming punctuation artifacts around extracted tokens."""
# punctuation.py
from __future__ import annotations

import re

# Leading wrappers we commonly see around string literals or tokens.
_LEADING = set('("\'{[<“”‘’')

# Trailing punctuation that often clings to tokens in text.
# (No functional duplicates; order doesn't matter in a set.)
_TRAILING = {
    ")",
    '"',
    "'",
    "}",
    "]",
    ">",
    ".",
    ",",
    ";",
    ":",
    "’",
    "”",
}

# Bracketed IPv6 literal matcher (RFC 3986 style), allowing zone IDs (RFC 6874).
# Examples: [2001:db8::1], [fe80::1%eth0], [::ffff:192.0.2.128]
_IPV6_CANDIDATE = re.compile(r"\[[0-9A-Fa-f:.%+-]+\]")


def _starts_with_ipv6_literal(value: str) -> bool:
    """Return True when *value* begins with a bracketed IPv6 literal."""

    if not value or value[0] != "[":
        return False

    match = _IPV6_CANDIDATE.match(value)
    return bool(match)


def _looks_like_ipv6_suffix(value: str) -> bool:
    """Return True when *value* ends with a bracketed IPv6 literal."""
    if not value:
        return False
    # Must end with a closing bracket
    if not value.endswith("]"):
        return False
    # Find the matching opening bracket to the last closing bracket
    open_index = value.rfind("[", 0, len(value) - 1)
    if open_index == -1:
        return False
    candidate = value[open_index:]
    return bool(_IPV6_CANDIDATE.fullmatch(candidate))

def strip_wrap_punct(text: str) -> str:
    """
    Remove leading/trailing wrapper punctuation from *text* without harming IPv6.

    This is intentionally dumb-but-safe: trim obvious wrappers and clingy punctuation
    that surround tokens extracted from prose or decompiled sources. If the string
    ends with a bracketed IPv6 literal, we preserve the closing bracket.
    """
    if not text:
        return text

    s = text.strip()
    if not s:
        return s

    # Remove leading punctuation wrappers greedily (quotes, parens, etc.).
    while s and s[0] in _LEADING:
        if s[0] == "[" and _starts_with_ipv6_literal(s):
            break
        s = s[1:].lstrip()

    if not s:
        return s

    # Remove trailing punctuation greedily, but do not strip a closing bracket
    # that completes a bracketed IPv6 literal at the end of the string.
    while s and s[-1] in _TRAILING:
        if s[-1] == "]" and _looks_like_ipv6_suffix(s):
            break
        s = s[:-1].rstrip()

    return s

__all__ = ["strip_wrap_punct"]