"""Risk scoring helpers for static analysis outputs."""

from __future__ import annotations

from .permission import (
    ScoringParams,
    collect_catalog_score_signals,
    get_scoring_params,
    permission_points_0_20,
    permission_risk_grade,
    permission_risk_score,
    permission_risk_score_detail,
    saturating_marginal,
    saturating_response,
)
from .scoring import (
    RiskAssessment,
    RiskConfig,
    RiskFactor,
    compute_risk_assessment,
)

__all__ = [
    "RiskAssessment",
    "RiskConfig",
    "RiskFactor",
    "compute_risk_assessment",
    "ScoringParams",
    "collect_catalog_score_signals",
    "get_scoring_params",
    "permission_points_0_20",
    "permission_risk_grade",
    "permission_risk_score",
    "permission_risk_score_detail",
    "saturating_marginal",
    "saturating_response",
]
