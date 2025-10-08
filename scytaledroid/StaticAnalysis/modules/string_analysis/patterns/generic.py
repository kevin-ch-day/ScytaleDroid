"""Generic secret indicator patterns."""

from __future__ import annotations

import re

from .base import DEFAULT_ORIGINS, StringPattern

PATTERNS: tuple[StringPattern, ...] = (
    StringPattern(
        name="jwt_token",
        description="Potential JSON Web Token",
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        category="auth",
        tags=("jwt", "token"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="generic_bearer",
        description="Potential bearer or API token",
        pattern=re.compile(r'(?i)\b(bearer|api[-_ ]?token|access[-_ ]?token)\b["\':=\s]+([A-Za-z0-9\-_.]{20,})'),
        category="auth",
        tags=("bearer", "token"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="generic_api_assignment",
        description="Potential API credential assignment",
        pattern=re.compile(r'(?i)secret["\':=\s]+([A-Za-z0-9\-_.]{16,})'),
        category="auth",
        tags=("secret", "assignment"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="basic_auth_url",
        description="Potential basic auth URL containing credentials",
        pattern=re.compile(r"https?://[^/\s:@]+:[^/\s@]+@[^/\s]+"),
        category="auth",
        tags=("basic_auth", "url"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="private_key_block",
        description="Potential embedded private key",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        category="crypto",
        tags=("private_key",),
        preferred_origins=DEFAULT_ORIGINS,
    ),
)

__all__ = ["PATTERNS"]
