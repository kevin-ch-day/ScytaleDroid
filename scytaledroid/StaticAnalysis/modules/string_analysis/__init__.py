"""File: scytaledroid/StaticAnalysis/modules/string_analysis/__init__.py

Shared utilities and re-exported helpers for the string-analysis pipeline."""

from __future__ import annotations

from .bucket_meta import BUCKET_LABELS, BUCKET_METADATA, BUCKET_ORDER, BucketMetadata
from .bucket_overview import build_bucket_overview
from .extractor import IndexedString, StringIndex, build_string_index
from .hit_record import StringHit
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
    "BucketMetadata",
    "BUCKET_LABELS",
    "BUCKET_METADATA",
    "BUCKET_ORDER",
    "IndexedString",
    "StringIndex",
    "StringHit",
    "EndpointMatch",
    "build_bucket_overview",
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
