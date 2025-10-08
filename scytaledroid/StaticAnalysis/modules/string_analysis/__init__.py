"""String analysis helpers for ScytaleDroid static analysis."""

from .extractor import IndexedString, StringIndex, build_string_index
from .matcher import (
    DEFAULT_SECRET_FILTERS,
    MatchBatch,
    MatchGroup,
    MatchRecord,
    MatchStatus,
    StringMatcher,
)
from .network import EndpointMatch, detect_tls_keywords, extract_endpoints

__all__ = [
    "IndexedString",
    "StringIndex",
    "EndpointMatch",
    "build_string_index",
    "DEFAULT_SECRET_FILTERS",
    "extract_endpoints",
    "detect_tls_keywords",
    "MatchBatch",
    "MatchGroup",
    "MatchRecord",
    "MatchStatus",
    "StringMatcher",
]
