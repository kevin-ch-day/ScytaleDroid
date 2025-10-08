"""Compatibility wrapper for legacy imports."""

from __future__ import annotations

from .indexing import build_string_index, IndexedString, StringIndex

__all__ = ["IndexedString", "StringIndex", "build_string_index"]
