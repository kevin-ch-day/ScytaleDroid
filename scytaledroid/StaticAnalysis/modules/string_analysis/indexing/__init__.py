"""Indexing utilities for string analysis."""

from .builder import build_string_index
from .models import IndexedString, StringIndex
from .sources import classify_origin_type, collect_file_strings, iterate_resource_strings
from .utils import (
    StringFragment,
    ensure_pattern,
    looks_textual,
    strings_from_binary,
    strings_from_text,
)

__all__ = [
    "IndexedString",
    "StringIndex",
    "build_string_index",
    "classify_origin_type",
    "collect_file_strings",
    "iterate_resource_strings",
    "StringFragment",
    "ensure_pattern",
    "looks_textual",
    "strings_from_binary",
    "strings_from_text",
]
