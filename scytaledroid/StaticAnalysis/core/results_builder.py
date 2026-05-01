"""Utilities for building static detector results without importing the pipeline."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from time import perf_counter

from .findings import Badge, DetectorResult, EvidencePointer, Finding


def make_detector_result(
    *,
    detector_id: str,
    section_key: str,
    status: Badge,
    started_at: float,
    findings: Sequence[Finding] | None = None,
    metrics: Mapping[str, object] | None = None,
    evidence: Sequence[EvidencePointer] | None = None,
    notes: Sequence[str] | None = None,
    subitems: Sequence[Mapping[str, object]] | None = None,
    raw_debug: str | None = None,
) -> DetectorResult:
    """Build a deterministic :class:`DetectorResult` instance."""
    duration = max(0.0, round(perf_counter() - started_at, 1))
    metrics_payload = dict(metrics or {})
    evidence_payload = tuple(evidence or ())
    notes_payload = tuple(note for note in notes or () if note)
    findings_payload = tuple(findings or ())
    subitems_payload = tuple(dict(item) for item in subitems) if subitems else None
    return DetectorResult(
        detector_id=detector_id,
        section_key=section_key,
        status=status,
        duration_sec=duration,
        metrics=metrics_payload,
        evidence=evidence_payload,
        notes=notes_payload,
        findings=findings_payload,
        subitems=subitems_payload,
        raw_debug=raw_debug,
    )


__all__ = ["make_detector_result"]
