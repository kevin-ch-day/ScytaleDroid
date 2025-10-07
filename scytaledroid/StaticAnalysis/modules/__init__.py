"""Modular helpers used by the static analysis pipeline."""

from .categories import resolve_category
from .string_analysis import build_string_index, IndexedString, StringIndex

__all__ = [
    "resolve_category",
    "build_string_index",
    "IndexedString",
    "StringIndex",
]
