"""Helpers for summarising MASVS compliance from detector findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from ..core.findings import Badge, Finding, MasvsCategory, SeverityLevel


_SEVERITY_WEIGHTS: Mapping[SeverityLevel, int] = {
    SeverityLevel.P0: 100,
    SeverityLevel.P1: 60,
    SeverityLevel.P2: 30,
    SeverityLevel.NOTE: 10,
}

_SEVERITY_ORDER: Mapping[SeverityLevel, int] = {
    SeverityLevel.P0: 0,
    SeverityLevel.P1: 1,
    SeverityLevel.P2: 2,
    SeverityLevel.NOTE: 3,
}

_BADGE_PRIORITY: Mapping[Badge, int] = {
    Badge.FAIL: 4,
    Badge.WARN: 3,
    Badge.INFO: 2,
    Badge.OK: 1,
    Badge.SKIPPED: 0,
}


@dataclass(frozen=True)
class FindingHighlight:
    """Condensed representation of a finding for compliance overviews."""

    finding_id: str
    title: str
    severity: SeverityLevel
    status: Badge
    because: str | None = None

    def to_dict(self) -> Mapping[str, object]:
        payload: dict[str, object] = {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
        }
        if self.because:
            payload["because"] = self.because
        return payload


@dataclass(frozen=True)
class MasvsCategorySummary:
    """Compliance state for a single MASVS category."""

    category: MasvsCategory
    status: Badge
    score: float
    total_findings: int
    severity_counts: Mapping[str, int]
    highlights: tuple[FindingHighlight, ...]

    def to_dict(self) -> Mapping[str, object]:
        return {
            "category": self.category.value,
            "status": self.status.value,
            "score": self.score,
            "total_findings": self.total_findings,
            "severity_counts": dict(self.severity_counts),
            "highlights": [highlight.to_dict() for highlight in self.highlights],
        }


@dataclass(frozen=True)
class MasvsComplianceSummary:
    """Aggregated compliance data across MASVS categories."""

    status: Badge
    score: float
    categories: tuple[MasvsCategorySummary, ...]

    def to_dict(self) -> Mapping[str, object]:
        return {
            "status": self.status.value,
            "score": self.score,
            "categories": [category.to_dict() for category in self.categories],
        }


def build_masvs_compliance_summary(
    findings: Sequence[Finding] | Iterable[Finding],
) -> MasvsComplianceSummary:
    """Return MASVS compliance summary data derived from *findings*."""

    buckets: dict[MasvsCategory, list[Finding]] = {
        category: [] for category in MasvsCategory
    }

    for finding in findings:
        category = getattr(finding, "category_masvs", None)
        if isinstance(category, MasvsCategory):
            buckets.setdefault(category, []).append(finding)
        else:
            buckets.setdefault(MasvsCategory.OTHER, []).append(finding)

    summaries: list[MasvsCategorySummary] = []
    total_score = 0.0
    counted_categories = 0
    worst_priority = _BADGE_PRIORITY[Badge.OK]

    for category in MasvsCategory:
        entries = buckets.get(category, [])
        if not entries and category is MasvsCategory.OTHER:
            continue

        summary = _summarise_category(category, entries)
        summaries.append(summary)

        counted_categories += 1
        total_score += summary.score
        worst_priority = max(worst_priority, _BADGE_PRIORITY[summary.status])

    if counted_categories:
        overall_score = round(total_score / counted_categories, 3)
    else:
        overall_score = 1.0
        worst_priority = _BADGE_PRIORITY[Badge.OK]

    overall_status = _badge_from_priority(worst_priority)
    return MasvsComplianceSummary(
        status=overall_status,
        score=overall_score,
        categories=tuple(summaries),
    )


def _summarise_category(
    category: MasvsCategory,
    findings: Sequence[Finding],
) -> MasvsCategorySummary:
    severity_counts: dict[str, int] = {level.value: 0 for level in SeverityLevel}
    penalty = 0

    for finding in findings:
        severity = getattr(finding, "severity_gate", SeverityLevel.NOTE)
        severity_counts.setdefault(severity.value, 0)
        severity_counts[severity.value] += 1
        penalty += _SEVERITY_WEIGHTS.get(severity, 10)

    total_findings = sum(severity_counts.values())
    status = _status_from_counts(severity_counts)

    score = max(0.0, 1.0 - min(100, penalty) / 100.0)
    score = round(score, 3)

    highlights = _build_highlights(findings)
    return MasvsCategorySummary(
        category=category,
        status=status,
        score=score,
        total_findings=total_findings,
        severity_counts=severity_counts,
        highlights=highlights,
    )


def _status_from_counts(counts: Mapping[str, int]) -> Badge:
    if counts.get(SeverityLevel.P0.value, 0):
        return Badge.FAIL
    if counts.get(SeverityLevel.P1.value, 0):
        return Badge.WARN
    if counts.get(SeverityLevel.P2.value, 0):
        return Badge.INFO
    if counts.get(SeverityLevel.NOTE.value, 0):
        return Badge.INFO
    return Badge.OK


def _build_highlights(findings: Sequence[Finding]) -> tuple[FindingHighlight, ...]:
    sorted_findings = sorted(
        findings,
        key=lambda item: (
            _SEVERITY_ORDER.get(getattr(item, "severity_gate", SeverityLevel.NOTE), 99),
            getattr(item, "title", ""),
        ),
    )

    highlights: list[FindingHighlight] = []
    for finding in sorted_findings[:3]:
        severity = getattr(finding, "severity_gate", SeverityLevel.NOTE)
        because = getattr(finding, "because", None)
        text = because.strip() if isinstance(because, str) else None
        highlights.append(
            FindingHighlight(
                finding_id=str(getattr(finding, "finding_id", "")),
                title=str(getattr(finding, "title", "")),
                severity=severity,
                status=getattr(finding, "status", Badge.INFO),
                because=text,
            )
        )
    return tuple(highlights)


def _badge_from_priority(priority: int) -> Badge:
    for badge, value in _BADGE_PRIORITY.items():
        if value == priority:
            return badge
    return Badge.OK


__all__ = [
    "FindingHighlight",
    "MasvsCategorySummary",
    "MasvsComplianceSummary",
    "build_masvs_compliance_summary",
]
