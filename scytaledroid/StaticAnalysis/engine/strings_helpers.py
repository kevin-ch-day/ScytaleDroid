"""Shared helpers for string analysis."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
from collections.abc import MutableMapping

from ..modules.string_analysis.constants import INTERNAL_HOST_SUFFIXES, JWT_FULLMATCH_PATTERN

_SOURCE_TYPE_MAP = {
    "code": "dex",
    "resource": "resource",
    "raw": "resource",
    "asset": "asset",
    "native": "asset",
}


def _short_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    frequency: MutableMapping[str, int] = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in frequency.values())


def _mask_value(value: str) -> str:
    if len(value) <= 8:
        return value
    return f"{value[:4]}…{value[-4:]}"


def _normalise_src(origin: str, origin_type: str, sha256: str) -> str:
    origin_label = origin or origin_type or "string"
    return f"{origin_label}@{sha256[:8]}"


def _source_type_for(entry_origin_type: str) -> str | None:
    return _SOURCE_TYPE_MAP.get(entry_origin_type)


def _host_risk_tag(host: str | None) -> str | None:
    if not host:
        return None
    lowered = host.lower()
    if lowered in {"localhost", "127.0.0.1", "::1"}:
        return "internal_domain"
    for suffix in INTERNAL_HOST_SUFFIXES:
        if lowered.endswith(f".{suffix}") or lowered == suffix:
            return "internal_domain"
    return "prod_domain"


def _ip_categories(host: str | None) -> tuple[str, ...]:
    if not host:
        return tuple()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return tuple()
    if ip.is_loopback:
        return ("localhost",)
    if ip.is_private:
        return ("ip_private",)
    if ip.is_global:
        return ("ip_public",)
    return tuple()


def _entropy_bucket(value: str, *, minimum: float) -> tuple[str | None, float]:
    if len(value) < 16:
        return (None, 0.0)
    stripped = value.strip()
    if not stripped or stripped.isdigit():
        return (None, 0.0)
    if re.fullmatch(r"[0-9a-fA-F]{16,}", stripped):
        return (None, 0.0)
    entropy_score = _entropy(stripped)
    threshold = max(minimum, 4.0)
    if entropy_score < threshold:
        return (None, entropy_score)
    if 4.0 <= entropy_score < 4.8:
        return ("low", entropy_score)
    if 4.8 <= entropy_score <= 5.5:
        return ("med", entropy_score)
    return ("high", entropy_score)


def _detect_jwt(value: str) -> bool:
    return bool(JWT_FULLMATCH_PATTERN.match(value.strip()))


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip().lower()
    return value in {"1", "true", "yes", "on"}


__all__ = [
    "_detect_jwt",
    "_entropy_bucket",
    "_env_flag",
    "_host_risk_tag",
    "_ip_categories",
    "_mask_value",
    "_normalise_src",
    "_short_hash",
    "_source_type_for",
]