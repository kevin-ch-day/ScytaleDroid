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
from .dynamic_correlation import (
    correlate_static_roots_with_dynamic_indicators,
    dynamic_indicators_from_report,
)
from .enrichment import (
    apply_pair_enrichment,
    classify_ownership,
    enrich_hit,
    infer_api_context,
    posture_summary_rows,
    summarize_xref_context,
)
from .allowlist import DEFAULT_POLICY_ROOT, NoisePolicy, load_noise_policy
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
from .matcher import (
    DEFAULT_SECRET_FILTERS,
    MatchBatch,
    MatchGroup,
    MatchRecord,
    MatchStatus,
    StringMatcher,
)
from .network import EndpointMatch, detect_tls_keywords, extract_endpoints
from .split_policy import (
    has_strong_secret_signal,
    is_split_member_context,
    should_skip_split_regex_work,
)
from .verifiers import VerificationHook, available_verification_hooks, verification_status_for

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
    "VerificationHook",
    "NoisePolicy",
    "DEFAULT_POLICY_ROOT",
    "load_noise_policy",
    "EndpointMatch",
    "apply_pair_enrichment",
    "build_bucket_overview",
    "build_string_index",
    "classify_ownership",
    "correlate_static_roots_with_dynamic_indicators",
    "dynamic_indicators_from_report",
    "normalise_index",
    "DEFAULT_SECRET_FILTERS",
    "extract_endpoints",
    "detect_tls_keywords",
    "has_strong_secret_signal",
    "is_split_member_context",
    "MatchBatch",
    "MatchGroup",
    "MatchRecord",
    "MatchStatus",
    "StringMatcher",
    "should_skip_split_regex_work",
    "available_verification_hooks",
    "enrich_hit",
    "infer_api_context",
    "posture_summary_rows",
    "summarise_analytics",
    "summarise_api_keys",
    "summarise_cleartext_hits",
    "summarise_cloud_refs",
    "summarise_endpoint_roots",
    "summarise_entropy",
    "summarize_xref_context",
    "verification_status_for",
]
