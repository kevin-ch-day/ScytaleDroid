"""File: scytaledroid/StaticAnalysis/modules/string_analysis/__init__.py

Shared utilities and re-exported helpers for the string-analysis pipeline."""

from __future__ import annotations

from .aggregates import (
    build_aggregates,
    summarise_analytics,
    summarise_api_keys,
    summarise_cleartext_hits,
    summarise_cloud_refs,
    summarise_endpoint_roots,
    summarise_entropy,
)
from .bucket_meta import BUCKET_LABELS, BUCKET_METADATA, BUCKET_ORDER, BucketMetadata
from .bucket_overview import build_bucket_overview
from .extractor import (
    CollectionMetrics,
    CollectionSummary,
    ExploratoryIssue,
    IndexedString,
    NormalizedString,
    StringIndex,
    build_string_index,
    normalise_index,
)
from .hit_record import StringHit
from .allowlist import NoisePolicy, load_noise_policy
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
    "build_aggregates",
    "IndexedString",
    "StringIndex",
    "NormalizedString",
    "ExploratoryIssue",
    "CollectionSummary",
    "CollectionMetrics",
    "StringHit",
    "NoisePolicy",
    "load_noise_policy",
    "EndpointMatch",
    "build_bucket_overview",
    "build_string_index",
    "normalise_index",
    "DEFAULT_SECRET_FILTERS",
    "extract_endpoints",
    "detect_tls_keywords",
    "MatchBatch",
    "MatchGroup",
    "MatchRecord",
    "MatchStatus",
    "StringMatcher",
    "summarise_analytics",
    "summarise_api_keys",
    "summarise_cleartext_hits",
    "summarise_cloud_refs",
    "summarise_endpoint_roots",
    "summarise_entropy",
]
