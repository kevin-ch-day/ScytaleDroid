"""Composable risk scoring helpers for static analysis reports."""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence, Sequence
from dataclasses import dataclass

from scytaledroid.StaticAnalysis.core.findings import SeverityLevel
from scytaledroid.StaticAnalysis.core.models import StaticAnalysisReport
from scytaledroid.StaticAnalysis.modules.permissions.analysis.curves import (
    independent_risk_combine,
)
from scytaledroid.StaticAnalysis.modules.permissions.analysis.name_patterns import (
    is_background_sensitive_name,
    is_health_permission_name,
)


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
    impacts = [float(config.secret_p0_weight)] * p0_secret_count
    impacts.extend([float(config.secret_p1_weight)] * p1_secret_count)
    score = int(round(independent_risk_combine(impacts, scale=float(config.secret_cap))))
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


def _permission_item_impact(
    entry: Mapping[str, object],
    *,
    high_weight: int,
) -> float:
    """Map one permission row onto the composite impact scale.

    After CVSS ISS per-permission scoring, runtime-dangerous names often land
    in the Medium band (weight ~60-79). Counting only ``band == High`` dropped
    CAMERA-class permissions from this heuristic surface.
    """

    name = str(entry.get("name") or "")
    band = str(entry.get("band") or entry.get("risk") or "").strip()
    try:
        numeric = int(entry.get("weight") or 0)
    except (TypeError, ValueError):
        numeric = 0
    profile = entry.get("profile") if isinstance(entry.get("profile"), Mapping) else {}
    high = (
        band == "High"
        or numeric >= 80
        or is_health_permission_name(name)
        or is_background_sensitive_name(name)
        or bool(profile.get("background_permission"))
    )
    if high:
        return float(high_weight)
    if band == "Medium" or numeric >= 60:
        return float(high_weight) * 0.6
    return 0.0


def _permission_factor(
    permissions: Sequence[Mapping[str, object]],
    *,
    config: RiskConfig,
) -> tuple[int, RiskFactor | None]:
    impacts = [
        _permission_item_impact(entry, high_weight=config.permission_weight)
        for entry in permissions
        if isinstance(entry, Mapping)
    ]
    impacts = [value for value in impacts if value > 0]
    if not impacts:
        return (0, None)
    score = int(round(independent_risk_combine(impacts, scale=float(config.permission_cap))))
    if score <= 0:
        return (0, None)
    factor = RiskFactor(
        "permissions",
        "high-risk permissions",
        score,
        detail=f"count={len(impacts)}",
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
