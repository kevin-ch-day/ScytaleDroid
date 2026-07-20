"""Dependency-free secret redaction helpers shared by logging boundaries."""

from __future__ import annotations

import re
from collections.abc import Mapping, MutableMapping
from typing import Any

REDACTED = "***REDACTED***"
_SENSITIVE_KEY_SUFFIXES = (
    "apikey",
    "accesstoken",
    "authorization",
    "clientsecret",
    "credential",
    "password",
    "passwd",
    "privatekey",
    "secret",
    "token",
)
_ASSIGNMENT_SECRET_RE = re.compile(
    r"(?P<label>\b(?:api[ _-]?key|x[ _-]?api[ _-]?key|authorization|access[ _-]?token|"
    r"client[ _-]?secret|(?:db[ _-]?)?pass(?:word|wd)?|secret|token)\b)"
    r"(?P<separator>\s*[:=]\s*)(?P<value>(?:bearer\s+)?[^\s,;]+)",
    flags=re.IGNORECASE,
)
_BEARER_TOKEN_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", flags=re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b")


def _is_sensitive_key(key: object) -> bool:
    """Match common secret-bearing key variants without hiding ordinary ``*_key`` fields."""

    compact = re.sub(r"[^a-z0-9]+", "", str(key).lower())
    return any(compact.endswith(suffix) for suffix in _SENSITIVE_KEY_SUFFIXES)


def redact_log_value(value: Any) -> Any:
    """Recursively redact values held under secret-bearing mapping keys."""

    if isinstance(value, Mapping):
        redacted: MutableMapping[str, Any] = type(value)()
        for key, val in value.items():
            if _is_sensitive_key(key):
                redacted[key] = REDACTED
            else:
                redacted[key] = redact_log_value(val)
        return redacted
    if isinstance(value, (list, tuple, set)):
        factory = type(value)
        return factory(redact_log_value(item) for item in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def redact_log_message(message: object) -> str:
    """Redact high-confidence secret literals from an emitted log message."""

    text = str(message)
    text = _ASSIGNMENT_SECRET_RE.sub(
        lambda match: f"{match.group('label')}{match.group('separator')}{REDACTED}", text
    )
    for pattern in (_BEARER_TOKEN_RE, _JWT_RE, _AWS_ACCESS_KEY_RE, _GOOGLE_API_KEY_RE, _GITHUB_TOKEN_RE):
        text = pattern.sub(REDACTED, text)
    return text


__all__ = ["redact_log_message", "redact_log_value"]
