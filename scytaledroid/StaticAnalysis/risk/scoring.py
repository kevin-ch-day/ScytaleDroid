"""Composable risk scoring helpers for static analysis reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, MutableSequence, Sequence

from scytaledroid.StaticAnalysis.core.findings import SeverityLevel
from scytaledroid.StaticAnalysis.core.models import StaticAnalysisReport


@dataclass(frozen=True)
class RiskFactor:
    """Individual contribution recorded in a composite risk score."""

    key: str
    label: str
    score: int
    detail: str | None = None


@dataclass(frozen=True)
class RiskAssessment:
    """Aggregate risk score with banding and contributing factors."""

    score: int
    band: str
    factors: tuple[RiskFactor, ...]

    def top_factor_labels(self, limit: int = 5) -> list[str]:
        return [factor.label for factor in self.factors[:limit]]

    def to_dict(self, *, limit: int = 5) -> Mapping[str, object]:
        return {
            "score": self.score,
            "band": self.band,
            "top_factors": self.top_factor_labels(limit),
        }


@dataclass(frozen=True)
class RiskConfig:
    """Tunables applied when deriving composite risk scores."""

    secret_p0_weight: int = 45
    secret_p1_weight: int = 25
    secret_cap: int = 75
    cleartext_weight: int = 20
    permission_weight: int = 5
    permission_cap: int = 20
    high_band_threshold: int = 70
    medium_band_threshold: int = 40


def _secret_factor(
    secrets: Sequence[Mapping[str, object]],
    *,
    config: RiskConfig,
) -> tuple[int, RiskFactor | None]:
    p0_secret_count = sum(
        1
        for entry in secrets
        if str(entry.get("severity")) == SeverityLevel.P0.value
    )
    p1_secret_count = sum(
        1
        for entry in secrets
        if str(entry.get("severity")) == SeverityLevel.P1.value
    )
    score = min(
        config.secret_cap,
        p0_secret_count * config.secret_p0_weight
        + p1_secret_count * config.secret_p1_weight,
    )
    if score <= 0:
        return (0, None)
    if p0_secret_count:
        label = "P0 secrets"
    elif p1_secret_count:
        label = "P1 secrets"
    else:
        label = "Secrets"
    return (score, RiskFactor("secrets", label, score))


def _cleartext_factor(
    network_summary: Mapping[str, object],
    report: StaticAnalysisReport,
    *,
    config: RiskConfig,
) -> tuple[int, RiskFactor | None]:
    http_count = int(network_summary.get("http_count") or 0)
    if http_count <= 0:
        return (0, None)

    uses_cleartext = report.manifest_flags.uses_cleartext_traffic is True
    if not uses_cleartext:
        return (0, None)

    declared = set(report.permissions.declared)
    if "android.permission.INTERNET" not in declared:
        return (0, None)

    score = config.cleartext_weight
    factor = RiskFactor(
        "cleartext",
        "cleartext traffic",
        score,
        detail=f"http_count={http_count}",
    )
    return (score, factor)


def _permission_factor(
    permissions: Sequence[Mapping[str, object]],
    *,
    config: RiskConfig,
) -> tuple[int, RiskFactor | None]:
    high_risk_permissions = sum(
        1 for entry in permissions if entry.get("risk") == "High"
    )
    if high_risk_permissions <= 0:
        return (0, None)
    score = min(config.permission_cap, high_risk_permissions * config.permission_weight)
    factor = RiskFactor(
        "permissions",
        "high-risk permissions",
        score,
        detail=f"count={high_risk_permissions}",
    )
    return (score, factor)


def _band_for_score(score: int, *, config: RiskConfig) -> str:
    if score >= config.high_band_threshold:
        return "High"
    if score >= config.medium_band_threshold:
        return "Medium"
    return "Low"


def compute_risk_assessment(
    *,
    permissions: Sequence[Mapping[str, object]],
    secrets: Sequence[Mapping[str, object]],
    network: Mapping[str, object],
    report: StaticAnalysisReport,
    config: RiskConfig | None = None,
) -> RiskAssessment:
    """Return a composite risk score for *report* based on collected signals."""

    effective_config = config or RiskConfig()
    score_total = 0
    factors: MutableSequence[RiskFactor] = []

    for contribution, factor in (
        _secret_factor(secrets, config=effective_config),
        _cleartext_factor(network, report, config=effective_config),
        _permission_factor(permissions, config=effective_config),
    ):
        score_total += contribution
        if factor is not None:
            factors.append(factor)

    score_total = min(score_total, 100)
    band = _band_for_score(score_total, config=effective_config)
    ordered_factors = tuple(sorted(factors, key=lambda f: f.score, reverse=True))

    return RiskAssessment(
        score=score_total,
        band=band,
        factors=ordered_factors,
    )


__all__ = [
    "RiskAssessment",
    "RiskConfig",
    "RiskFactor",
    "compute_risk_assessment",
]

