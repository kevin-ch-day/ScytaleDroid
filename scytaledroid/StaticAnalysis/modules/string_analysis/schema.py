"""Structured payload definitions for the string intelligence pipeline."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping, MutableMapping


@dataclass(frozen=True)
class EvidenceRef:
    """Reference to a concrete evidence blob in the APK."""

    path: str
    offset: int | None = None
    sha256: str | None = None

    @property
    def pointer(self) -> str:
        suffix = "na" if self.offset is None else str(self.offset)
        return f"{self.path}@{suffix}"


@dataclass(frozen=True)
class Observation:
    """Single risk indicator emitted by the string post-processor."""

    value: str
    src: str
    tags: tuple[str, ...]
    category: str
    confidence: str
    evidence: EvidenceRef
    context: str
    sha_short: str
    host: str | None = None
    decoded: str | None = None

    def to_dict(self) -> Mapping[str, object]:
        payload: MutableMapping[str, object] = {
            "value": self.value,
            "src": self.src,
            "tags": list(self.tags),
            "category": self.category,
            "confidence": self.confidence,
            "evidence": {
                "path": self.evidence.path,
                "offset": self.evidence.offset,
                "pointer": self.evidence.pointer,
            },
            "context": self.context,
            "sha_short": self.sha_short,
        }
        if self.host:
            payload["host"] = self.host
        if self.decoded:
            payload["decoded"] = self.decoded
        if self.evidence.sha256:
            payload["evidence"]["sha256"] = self.evidence.sha256
        return payload


@dataclass(frozen=True)
class SniSummary:
    """Top-level payload returned by ``post.py`` helpers."""

    risk_relevant: tuple[Observation, ...] = ()
    documentary: tuple[Observation, ...] = ()
    scorecard: "Scorecard | None" = None

    def to_dict(self) -> Mapping[str, object]:
        payload: MutableMapping[str, object] = {
            "risk_relevant": [obs.to_dict() for obs in self.risk_relevant],
            "documentary": [obs.to_dict() for obs in self.documentary],
        }
        if self.scorecard:
            payload["scorecard"] = self.scorecard.to_dict()
        return payload


@dataclass(frozen=True)
class TestResult:
    """Calculated score for a single SNI test."""

    test_id: str
    name: str
    category: str
    score: float
    grade: str
    rationale: str
    observations: tuple[Observation, ...]
    evidence: tuple[EvidenceRef, ...]
    uncertainty: float

    def to_dict(self) -> Mapping[str, object]:
        return {
            "id": self.test_id,
            "name": self.name,
            "category": self.category,
            "score": round(self.score, 2),
            "grade": self.grade,
            "rationale": self.rationale,
            "uncertainty": round(self.uncertainty, 2),
            "evidence": [
                {
                    "path": ref.path,
                    "offset": ref.offset,
                    "pointer": ref.pointer,
                    **({"sha256": ref.sha256} if ref.sha256 else {}),
                }
                for ref in self.evidence
            ],
        }


@dataclass(frozen=True)
class CategoryRollup:
    """Aggregated score for a logical category of tests."""

    category: str
    label: str
    score: float
    grade: str
    tests: tuple[str, ...]

    def to_dict(self) -> Mapping[str, object]:
        return {
            "category": self.category,
            "label": self.label,
            "score": round(self.score, 2),
            "grade": self.grade,
            "tests": list(self.tests),
        }


@dataclass(frozen=True)
class FinalAssessment:
    """Overall risk summary combining category scores."""

    profile: str
    score: float
    grade: str
    weights: Mapping[str, float]
    weights_hash: str
    uncertainty: float

    def to_dict(self) -> Mapping[str, object]:
        return {
            "profile": self.profile,
            "score": round(self.score, 2),
            "grade": self.grade,
            "weights": dict(self.weights),
            "weights_hash": self.weights_hash,
            "uncertainty": round(self.uncertainty, 2),
        }


@dataclass(frozen=True)
class Scorecard:
    """Full scoring output for the String Intelligence stage."""

    tests: tuple[TestResult, ...]
    categories: tuple[CategoryRollup, ...]
    final: FinalAssessment

    def to_dict(self) -> Mapping[str, object]:
        return {
            "tests": [result.to_dict() for result in self.tests],
            "categories": [rollup.to_dict() for rollup in self.categories],
            "final": self.final.to_dict(),
        }


def hash_weights(weights: Mapping[str, float]) -> str:
    """Return a short stable hash for *weights*."""

    normalized = {key: round(value, 6) for key, value in sorted(weights.items())}
    digest = hashlib.sha1(json.dumps(normalized, sort_keys=True).encode("utf-8")).hexdigest()
    return digest[:8]


__all__ = [
    "EvidenceRef",
    "Observation",
    "SniSummary",
    "TestResult",
    "CategoryRollup",
    "FinalAssessment",
    "Scorecard",
    "hash_weights",
]
