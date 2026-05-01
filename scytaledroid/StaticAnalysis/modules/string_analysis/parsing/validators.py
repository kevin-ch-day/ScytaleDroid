"""Validation helpers for host candidates."""

from __future__ import annotations

import ipaddress
import re

from ..constants import HOST_PATTERN
from ..tags.placeholders import PLACEHOLDER_TOKENS

_PLACEHOLDER_SUFFIXES = (".test", ".example", ".invalid", ".localhost")


def is_ip(host: str | None) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def is_localhost(host: str | None) -> bool:
    if not host:
        return False
    lowered = host.strip().lower()
    if lowered in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(lowered).is_loopback
    except ValueError:
        return False


def is_private_ip(host: str | None) -> bool:
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def looks_like_domain(host: str | None) -> bool:
    if not host:
        return False
    candidate = host.strip().lower().strip(".")
    if not candidate or candidate in {"localhost"}:
        return False
    if candidate.endswith(_PLACEHOLDER_SUFFIXES):
        return False
    if candidate.count(".") < 1:
        return False
    if len(candidate) < 4:
        return False
    return bool(HOST_PATTERN.match(candidate))


def is_placeholder(value: str | None) -> bool:
    if not value:
        return False
    token = value.strip().lower()
    if not token:
        return True
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1]
        if is_ip(inner):
            return False
        token = inner
    if token in PLACEHOLDER_TOKENS:
        return True
    if token.startswith("%") and token.endswith("s"):
        return True
    if token.startswith("{") and token.endswith("}"):
        return True
    if token in {"dev", "test"}:
        return True
    if "." not in token:
        if token in {"localhost"}:
            return True
        if is_ip(token):
            return False
        if len(token) <= 24:
            return True
        return False
    if re.fullmatch(r"[a-z]\d?", token):
        return True
    return False


def is_real_host(host: str | None) -> bool:
    if not host:
        return False
    if is_placeholder(host):
        return False
    if is_ip(host):
        try:
            return not ipaddress.ip_address(host).is_private
        except ValueError:
            return False
    if is_localhost(host):
        return True
    return looks_like_domain(host)


__all__ = [
    "is_ip",
    "is_localhost",
    "looks_like_domain",
    "is_real_host",
    "is_placeholder",
    "is_private_ip",
]