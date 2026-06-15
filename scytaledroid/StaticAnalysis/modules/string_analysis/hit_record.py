"""File: scytaledroid/StaticAnalysis/modules/string_analysis/hit_record.py

Structured record definition for categorised string hits."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StringHit:
    """A categorised string hit captured during static analysis."""

    bucket: str
    value: str
    src: str
    tag: str | None = None
    sha256: str | None = None
    masked: str | None = None
    finding_type: str | None = None
    provider: str | None = None
    risk_tag: str | None = None
    confidence: str | None = None
    scheme: str | None = None
    root_domain: str | None = None
    resource_name: str | None = None
    source_type: str | None = None
    sample_hash: str | None = None
    xref_context: str | None = None
    api_context: str | None = None
    posture: str | None = None
    ownership_class: str | None = None
    pair_group: str | None = None
    verification_status: str | None = None
    dynamic_corroboration: str | None = None


__all__ = ["StringHit"]
