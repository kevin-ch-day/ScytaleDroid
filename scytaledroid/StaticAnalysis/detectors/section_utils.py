"""Shared helpers for section-oriented detector metrics."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from ..core.findings import Badge, DetectorResult, EvidencePointer


def placeholder_result(
    *,
    detector_id: str,
    section_key: str,
    summary: str = "Detector not yet implemented",
    status: Badge = Badge.SKIPPED,
    notes: Sequence[str] | None = None,
) -> DetectorResult:
    """Build a deterministic placeholder result for unfinished detectors."""

    metrics: dict[str, object] = {
        "summary": summary,
        "status": status.value,
    }
    note_lines = tuple(notes) if notes else tuple()
    return DetectorResult(
        detector_id=detector_id,
        section_key=section_key,
        status=status,
        duration_sec=0.0,
        metrics=metrics,
        evidence=tuple(),
        notes=note_lines,
    )


def merge_metrics(
    base: Mapping[str, object],
    overrides: Mapping[str, object],
) -> dict[str, object]:
    """Return a merged copy of *base* with keys from *overrides* applied."""

    result: dict[str, object] = dict(base)
    for key, value in overrides.items():
        result[key] = value
    return result


def normalise_evidence(
    evidence: Iterable[Mapping[str, object]]
) -> tuple[EvidencePointer, ...]:
    """Convert evidence iterables to a deterministic tuple of pointers."""

    pointers = []
    for entry in evidence:
        if not isinstance(entry, Mapping):
            continue
        pointer = EvidencePointer(
            location=str(entry.get("location") or entry.get("path") or "unknown"),
            hash_short=_coerce_optional_str(entry.get("hash_short")),
            description=_coerce_optional_str(entry.get("description")),
            extra=dict(entry.get("extra", {})) if isinstance(entry.get("extra"), Mapping) else {},
        )
        pointers.append(pointer)
    return tuple(pointers)


def _coerce_optional_str(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    return str(value)


__all__ = [
    "placeholder_result",
    "merge_metrics",
    "normalise_evidence",
]