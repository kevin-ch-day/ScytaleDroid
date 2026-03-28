"""Shared helpers for normalizing and validating package names."""

from __future__ import annotations

from scytaledroid.Utils.LoggingUtils import logging_utils as log

_SUSPICIOUS_TOKENS = ("/", "\\", "=", "base.apk")
_SEEN_PACKAGE_WARNINGS: set[tuple[str, str, str]] = set()


def normalize_package_name(value: str, *, context: str = "database") -> str:
    """Return a normalized package name (trimmed + lowercase)."""

    cleaned = (value or "").strip().lower()
    if not cleaned:
        return ""

    if _looks_suspicious(cleaned):
        _warn_package_name_once(
            context=context,
            warning_type="suspicious",
            original=value,
            cleaned=cleaned,
            message=f"Suspicious package_name '{value}' encountered; normalizing to '{cleaned}'.",
        )
    elif cleaned.endswith(".apk"):
        _warn_package_name_once(
            context=context,
            warning_type="apk_suffix",
            original=value,
            cleaned=cleaned,
            message=f"package_name '{value}' ends with .apk; allowing but flagging for review.",
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


def _warn_package_name_once(
    *,
    context: str,
    warning_type: str,
    original: str,
    cleaned: str,
    message: str,
) -> None:
    key = (context, warning_type, cleaned)
    if key in _SEEN_PACKAGE_WARNINGS:
        return
    _SEEN_PACKAGE_WARNINGS.add(key)
    log.warning(message, category=context)


__all__ = [
    "normalize_package_name",
    "is_suspicious_package_name",
]
