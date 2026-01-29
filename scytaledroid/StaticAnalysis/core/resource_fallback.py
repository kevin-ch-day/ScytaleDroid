"""Centralized APK resource fallback logic (Androguard -> aapt2)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from scytaledroid.StaticAnalysis._androguard import APK, open_apk_safely
from scytaledroid.StaticAnalysis.engine import aapt2_fallback


@dataclass(frozen=True)
class ApkResourceFallback:
    apk: APK | None
    warnings: list[str]
    fallback_used: bool
    fallback_reason: str | None
    fallback_meta: dict[str, object] | None

    def as_metadata(self) -> dict[str, object]:
        return {
            "resource_fallback": {
                "fallback_used": self.fallback_used,
                "fallback_reason": self.fallback_reason,
                "aapt2_available": aapt2_fallback.has_aapt2(),
                "warning_count": len(self.warnings),
            }
        }


def open_apk_with_fallback(apk_path: str | Path) -> ApkResourceFallback:
    """Open APK with Androguard; if it fails, attempt aapt2 metadata fallback."""

    warnings: list[str] = []
    try:
        apk, warnings = open_apk_safely(str(apk_path))
        return ApkResourceFallback(
            apk=apk,
            warnings=warnings,
            fallback_used=False,
            fallback_reason=None,
            fallback_meta=None,
        )
    except Exception:
        fallback_meta = aapt2_fallback.extract_metadata(str(apk_path))
        return ApkResourceFallback(
            apk=None,
            warnings=warnings,
            fallback_used=bool(fallback_meta),
            fallback_reason="androguard_open_failed" if fallback_meta else "androguard_open_failed_no_aapt2",
            fallback_meta=fallback_meta,
        )


def merge_metadata(meta: Mapping[str, Any], fallback: ApkResourceFallback) -> dict[str, object]:
    """Return a shallow metadata copy with fallback fields merged in."""

    merged = dict(meta) if isinstance(meta, Mapping) else {}
    merged.update(fallback.as_metadata())
    if fallback.warnings:
        merged.setdefault("resource_bounds_warnings", [])
        if isinstance(merged["resource_bounds_warnings"], list):
            for line in fallback.warnings:
                if line not in merged["resource_bounds_warnings"]:
                    merged["resource_bounds_warnings"].append(line)
    if fallback.fallback_meta:
        merged.setdefault("resource_fallback_meta", fallback.fallback_meta)
    return merged


__all__ = ["ApkResourceFallback", "open_apk_with_fallback", "merge_metadata"]
