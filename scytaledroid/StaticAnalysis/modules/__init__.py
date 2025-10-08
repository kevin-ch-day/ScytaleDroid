"""Modular helpers used by the static analysis pipeline."""

from .categories import resolve_category
from .masvs import (
    FindingHighlight,
    MasvsCategorySummary,
    MasvsComplianceSummary,
    build_masvs_compliance_summary,
)
from .string_analysis import (
    EndpointMatch,
    IndexedString,
    StringIndex,
    build_string_index,
    detect_tls_keywords,
    extract_endpoints,
)

__all__ = [
    "resolve_category",
    "build_masvs_compliance_summary",
    "MasvsComplianceSummary",
    "MasvsCategorySummary",
    "FindingHighlight",
    "build_string_index",
    "IndexedString",
    "StringIndex",
    "EndpointMatch",
    "extract_endpoints",
    "detect_tls_keywords",
]
