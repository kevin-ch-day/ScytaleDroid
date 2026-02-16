"""Persistence contracts for static analysis scientific writes."""

from __future__ import annotations

SCIENTIFIC_UOW_TABLES = frozenset(
    {
        # Identity/dimension rows that may be created while resolving run identity.
        "apps",
        "app_versions",
        # Core run identity / status.
        "static_analysis_runs",
        # Canonical findings and observation rows.
        "static_analysis_findings",
        "findings",
        "static_correlation_results",
        "static_fileproviders",
        "static_provider_acl",
        # Risk and permission outputs.
        "risk_scores",
        "static_permission_risk",
        "static_permission_matrix",
        # Metrics + contributors + section writers.
        "buckets",
        "metrics",
        "contributors",
        "masvs_control_coverage",
        "static_findings_summary",
        "static_findings",
        "static_string_summary",
        "static_string_samples",
        "static_string_selected_samples",
        "static_string_sample_sets",
        "doc_hosts",
    }
)

LEDGER_TABLES = frozenset(
    {
        "static_persistence_failures",
    }
)

AUTHORITATIVE_RUN_STATES = frozenset({"STARTED", "COMPLETED", "FAILED"})

LEGACY_RUN_STATE_MAP = {
    "RUNNING": "STARTED",
    "ABORTED": "FAILED",
    "DONE": "COMPLETED",
}


def normalize_run_status(status: str | None) -> str:
    token = str(status or "").strip().upper()
    if token in AUTHORITATIVE_RUN_STATES:
        return token
    return LEGACY_RUN_STATE_MAP.get(token, "FAILED")


__all__ = [
    "SCIENTIFIC_UOW_TABLES",
    "LEDGER_TABLES",
    "AUTHORITATIVE_RUN_STATES",
    "LEGACY_RUN_STATE_MAP",
    "normalize_run_status",
]
