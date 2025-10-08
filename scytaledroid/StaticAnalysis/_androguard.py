"""Compatibility helpers for importing androguard primitives."""

from __future__ import annotations

try:  # pragma: no cover - prefer modern androguard layout
    from androguard.core.apk import APK, FileNotPresent
except ImportError:  # pragma: no cover - legacy androguard (<4)
    from androguard.core.bytecodes.apk import APK, FileNotPresent  # type: ignore[attr-defined]

__all__ = ["APK", "FileNotPresent"]
