"""Common data structures for static-analysis findings and severity levels."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, MutableMapping, Optional, Sequence


class SeverityLevel(str, Enum):
    """Severity gates used to prioritise remediation."""

    P0 = "P0"  # Blocker
    P1 = "P1"  # Release risk
    P2 = "P2"  # Hardening
    NOTE = "NOTE"  # Informational / context only


class MasvsCategory(str, Enum):
    """MASVS categories used for mapping findings to standards."""

    NETWORK = "NETWORK"
    PLATFORM = "PLATFORM"
    STORAGE = "STORAGE"
    PRIVACY = "PRIVACY"
    CRYPTO = "CRYPTO"
    RESILIENCE = "RESILIENCE"
    OTHER = "OTHER"


class Badge(str, Enum):
    """Presentation badges for detector status."""

    OK = "OK"
    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class EvidencePointer:
    """Lightweight pointer describing where evidence for a finding lives."""

    location: str
    hash_short: Optional[str] = None
    description: Optional[str] = None
    extra: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> MutableMapping[str, object]:
        payload: MutableMapping[str, object] = {
            "location": self.location,
            "hash_short": self.hash_short,
            "description": self.description,
            "extra": dict(self.extra),
        }
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "EvidencePointer":
        location = _coerce_optional_str(payload.get("location")) or ""
        return cls(
            location=location,
            hash_short=_coerce_optional_str(payload.get("hash_short")),
            description=_coerce_optional_str(payload.get("description")),
            extra=_coerce_mapping(payload.get("extra")),
        )


@dataclass(frozen=True)
class Finding:
    """Normalized representation of a detector or correlation output."""

    finding_id: str
    title: str
    severity_gate: SeverityLevel
    category_masvs: MasvsCategory
    status: Badge
    because: str
    evidence: Sequence[EvidencePointer] = field(default_factory=tuple)
    remediate: Optional[str] = None
    metrics: Mapping[str, object] = field(default_factory=dict)
    tags: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> MutableMapping[str, object]:
        payload: MutableMapping[str, object] = {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity_gate": self.severity_gate.value,
            "category_masvs": self.category_masvs.value,
            "status": self.status.value,
            "because": self.because,
            "evidence": [pointer.to_dict() for pointer in self.evidence],
            "remediate": self.remediate,
            "metrics": dict(self.metrics),
            "tags": list(self.tags),
        }
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "Finding":
        severity_raw = payload.get("severity_gate") or SeverityLevel.NOTE.value
        try:
            severity = SeverityLevel(severity_raw)
        except ValueError:
            severity = SeverityLevel.NOTE

        category_raw = payload.get("category_masvs") or MasvsCategory.OTHER.value
        try:
            category = MasvsCategory(category_raw)
        except ValueError:
            category = MasvsCategory.OTHER

        status_raw = payload.get("status") or Badge.INFO.value
        try:
            status = Badge(status_raw)
        except ValueError:
            status = Badge.INFO

        evidence_payload = payload.get("evidence")
        evidence: Sequence[EvidencePointer]
        if isinstance(evidence_payload, Sequence) and not isinstance(
            evidence_payload, (str, bytes)
        ):
            evidence = tuple(
                EvidencePointer.from_dict(entry)
                for entry in evidence_payload
                if isinstance(entry, Mapping)
            )
        else:
            evidence = tuple()

        tags_payload = payload.get("tags")
        if isinstance(tags_payload, Sequence) and not isinstance(tags_payload, (str, bytes)):
            tags = tuple(str(entry) for entry in tags_payload)
        else:
            tags = tuple()

        metrics_payload = payload.get("metrics")
        metrics = metrics_payload if isinstance(metrics_payload, Mapping) else {}

        return cls(
            finding_id=str(payload.get("finding_id") or ""),
            title=str(payload.get("title") or ""),
            severity_gate=severity,
            category_masvs=category,
            status=status,
            because=str(payload.get("because") or ""),
            evidence=evidence,
            remediate=_coerce_optional_str(payload.get("remediate")),
            metrics=metrics,
            tags=tags,
        )


@dataclass(frozen=True)
class DetectorResult:
    """Aggregated result from a detector run."""

    detector_id: str
    section_key: str
    status: Badge
    duration_sec: float
    metrics: Mapping[str, object] = field(default_factory=dict)
    evidence: Sequence[EvidencePointer] = field(default_factory=tuple)
    notes: Sequence[str] = field(default_factory=tuple)
    findings: Sequence[Finding] = field(default_factory=tuple)
    subitems: Optional[Sequence[Mapping[str, object]]] = None
    raw_debug: Optional[str] = None

    def to_dict(self) -> MutableMapping[str, object]:
        return {
            "detector_id": self.detector_id,
            "section_key": self.section_key,
            "status": self.status.value,
            "duration_sec": self.duration_sec,
            "findings": [finding.to_dict() for finding in self.findings],
            "metrics": dict(self.metrics),
            "evidence": [pointer.to_dict() for pointer in self.evidence],
            "notes": list(self.notes),
            "subitems": list(self.subitems) if self.subitems else None,
            "raw_debug": self.raw_debug,
        }


def _coerce_optional_str(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    return str(value)


def _coerce_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


__all__ = [
    "SeverityLevel",
    "MasvsCategory",
    "Badge",
    "EvidencePointer",
    "Finding",
    "DetectorResult",
]
