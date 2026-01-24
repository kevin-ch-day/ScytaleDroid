"""Shared helpers for normalizing and validating package names."""

from __future__ import annotations

from scytaledroid.Utils.LoggingUtils import logging_utils as log


_SUSPICIOUS_TOKENS = ("/", "\\", "=", "base.apk", ".apk")


def normalize_package_name(value: str, *, context: str = "database") -> str:
    """Return a normalized package name (trimmed + lowercase)."""

    cleaned = (value or "").strip().lower()
    if not cleaned:
        return ""

    if _looks_suspicious(cleaned):
        log.warning(
            f"Suspicious package_name '{value}' encountered; normalizing to '{cleaned}'.",
            category=context,
        )
    return cleaned


def is_suspicious_package_name(value: str) -> bool:
    """Return True when a package_name looks like a path or artifact."""

    cleaned = (value or "").strip().lower()
    return _looks_suspicious(cleaned)


def _looks_suspicious(cleaned: str) -> bool:
    if not cleaned:
        return True
    if " " in cleaned:
        return True
    for token in _SUSPICIOUS_TOKENS:
        if token in cleaned:
            return True
    return False


__all__ = [
    "normalize_package_name",
    "is_suspicious_package_name",
]
