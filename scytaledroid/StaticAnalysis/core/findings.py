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


@dataclass(frozen=True)
class EvidencePointer:
    """Lightweight pointer describing where evidence for a finding lives."""

    file_path: Optional[str] = None
    line_number: Optional[int] = None
    manifest_xpath: Optional[str] = None
    string_hash: Optional[str] = None
    description: Optional[str] = None
    extra: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> MutableMapping[str, object]:
        payload: MutableMapping[str, object] = {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "manifest_xpath": self.manifest_xpath,
            "string_hash": self.string_hash,
            "description": self.description,
            "extra": dict(self.extra),
        }
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "EvidencePointer":
        return cls(
            file_path=_coerce_optional_str(payload.get("file_path")),
            line_number=_coerce_optional_int(payload.get("line_number")),
            manifest_xpath=_coerce_optional_str(payload.get("manifest_xpath")),
            string_hash=_coerce_optional_str(payload.get("string_hash")),
            description=_coerce_optional_str(payload.get("description")),
            extra=_coerce_mapping(payload.get("extra")),
        )


@dataclass(frozen=True)
class Finding:
    """Normalized representation of a detector or correlation output."""

    finding_id: str
    title: str
    summary: str
    detector_id: str
    severity: SeverityLevel
    masvs_category: MasvsCategory = MasvsCategory.OTHER
    evidence: EvidencePointer = field(default_factory=EvidencePointer)
    remediation: Optional[str] = None
    correlation_chain: Sequence[str] = field(default_factory=tuple)
    tags: Sequence[str] = field(default_factory=tuple)
    supporting_data: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> MutableMapping[str, object]:
        payload: MutableMapping[str, object] = {
            "finding_id": self.finding_id,
            "title": self.title,
            "summary": self.summary,
            "detector_id": self.detector_id,
            "severity": self.severity.value,
            "masvs_category": self.masvs_category.value,
            "evidence": self.evidence.to_dict(),
            "remediation": self.remediation,
            "correlation_chain": list(self.correlation_chain),
            "tags": list(self.tags),
            "supporting_data": dict(self.supporting_data),
        }
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "Finding":
        severity_raw = payload.get("severity") or SeverityLevel.NOTE.value
        try:
            severity = SeverityLevel(severity_raw)
        except ValueError:
            severity = SeverityLevel.NOTE

        masvs_raw = payload.get("masvs_category") or MasvsCategory.OTHER.value
        try:
            masvs = MasvsCategory(masvs_raw)
        except ValueError:
            masvs = MasvsCategory.OTHER

        evidence_payload = payload.get("evidence")
        evidence = (
            EvidencePointer.from_dict(evidence_payload)
            if isinstance(evidence_payload, Mapping)
            else EvidencePointer()
        )

        correlation = payload.get("correlation_chain")
        if isinstance(correlation, Sequence) and not isinstance(correlation, (str, bytes)):
            correlation_chain = tuple(str(entry) for entry in correlation)
        else:
            correlation_chain = tuple()

        tags_raw = payload.get("tags")
        if isinstance(tags_raw, Sequence) and not isinstance(tags_raw, (str, bytes)):
            tags = tuple(str(tag) for tag in tags_raw)
        else:
            tags = tuple()

        supporting_raw = payload.get("supporting_data")
        supporting = supporting_raw if isinstance(supporting_raw, Mapping) else {}

        return cls(
            finding_id=str(payload.get("finding_id") or ""),
            title=str(payload.get("title") or ""),
            summary=str(payload.get("summary") or ""),
            detector_id=str(payload.get("detector_id") or ""),
            severity=severity,
            masvs_category=masvs,
            evidence=evidence,
            remediation=_coerce_optional_str(payload.get("remediation")),
            correlation_chain=correlation_chain,
            tags=tags,
            supporting_data=supporting,
        )


@dataclass(frozen=True)
class DetectorResult:
    """Aggregated result from a detector run."""

    detector_id: str
    findings: Sequence[Finding] = field(default_factory=tuple)
    metrics: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> MutableMapping[str, object]:
        return {
            "detector_id": self.detector_id,
            "findings": [finding.to_dict() for finding in self.findings],
            "metrics": dict(self.metrics),
        }


def _coerce_optional_str(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    return str(value)


def _coerce_optional_int(value: object) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


__all__ = [
    "SeverityLevel",
    "MasvsCategory",
    "EvidencePointer",
    "Finding",
    "DetectorResult",
]
