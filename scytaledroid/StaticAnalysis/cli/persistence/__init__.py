"""Persistence helpers used by the CLI."""

from .run_envelope import RunEnvelope, extract_run_profiles, first_non_empty_str, prepare_run_envelope
from .metrics_writer import (
    MetricsBundle,
    compute_metrics_bundle,
    write_buckets,
    write_metrics,
    write_contributors,
)
from .static_findings_writer import coerce_severity_counts, persist_static_findings
from .strings_writer import normalise_string_counts, persist_string_summary
from .findings_writer import (
    compute_cvss_base,
    derive_masvs_tag,
    extract_rule_hint,
    persist_findings,
    persist_masvs_controls,
)

__all__ = [
    "RunEnvelope",
    "coerce_severity_counts",
    "compute_cvss_base",
    "compute_metrics_bundle",
    "derive_masvs_tag",
    "extract_rule_hint",
    "extract_run_profiles",
    "first_non_empty_str",
    "normalise_string_counts",
    "persist_findings",
    "persist_masvs_controls",
    "persist_static_findings",
    "persist_string_summary",
    "prepare_run_envelope",
    "MetricsBundle",
    "write_buckets",
    "write_contributors",
    "write_metrics",
]
