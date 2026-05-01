"""Shared helpers for normalizing and validating package names."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.Utils.LoggingUtils import logging_utils as log

_SUSPICIOUS_TOKENS = ("/", "\\", "=", "base.apk")
_SEEN_PACKAGE_WARNINGS: set[tuple[str, str, str]] = set()


@dataclass(frozen=True)
class PackageIdentity:
    """Normalized package identity plus retained source details."""

    normalized_package_name: str
    manifest_package_name: str
    package_name: str
    package_case_mismatch: bool
    invalid: bool = False

    def as_metadata(self) -> dict[str, object]:
        payload: dict[str, object] = {}
        if self.normalized_package_name:
            payload["normalized_package_name"] = self.normalized_package_name
        if self.manifest_package_name:
            payload["manifest_package_name"] = self.manifest_package_name
        if self.package_name:
            payload["package_name"] = self.package_name
        if self.package_case_mismatch:
            payload["package_case_mismatch"] = True
        if self.invalid:
            payload["package_identity_invalid"] = True
        return payload


def normalize_package_name(value: str, *, context: str = "database") -> str:
    """Return a normalized package name (trimmed + lowercase)."""

    cleaned = (value or "").strip().lower()
    if not cleaned:
        return ""
    if cleaned.isdigit():
        _warn_package_name_once(
            context=context,
            warning_type="numeric_only",
            original=value,
            cleaned=cleaned,
            message=f"Rejecting numeric-only package_name '{value}'.",
        )
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


def resolve_package_identity(
    value: str,
    *,
    context: str = "database",
    fallback_to_original: bool = True,
) -> PackageIdentity:
    """Return a structured package identity for *value*."""

    manifest_package_name = str(value or "").strip()
    normalized_package_name = normalize_package_name(manifest_package_name, context=context)
    package_name = normalized_package_name
    if not package_name and fallback_to_original:
        package_name = manifest_package_name
    return PackageIdentity(
        normalized_package_name=normalized_package_name,
        manifest_package_name=manifest_package_name,
        package_name=package_name,
        package_case_mismatch=bool(
            normalized_package_name
            and manifest_package_name
            and normalized_package_name != manifest_package_name
        ),
        invalid=not bool(normalized_package_name),
    )


def is_suspicious_package_name(value: str) -> bool:
    """Return True when a package_name looks like a path or artifact."""

    cleaned = (value or "").strip().lower()
    return _looks_suspicious(cleaned) or cleaned.endswith(".apk")


def is_invalid_package_name(value: str) -> bool:
    """Return True when a package token should be rejected outright."""

    cleaned = (value or "").strip().lower()
    return (not cleaned) or cleaned.isdigit()


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
    "is_invalid_package_name",
    "normalize_package_name",
    "PackageIdentity",
    "resolve_package_identity",
    "is_suspicious_package_name",
]
