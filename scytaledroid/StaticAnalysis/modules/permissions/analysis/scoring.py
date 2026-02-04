"""Backwards-compatible wrappers for permission risk scoring.

This module historically hosted the permission-scoring engine. The canonical
implementation now lives in ``scytaledroid.StaticAnalysis.risk.permission``.
Imports remain to avoid breaking older code paths while the new risk package is
rolled out.
"""

from __future__ import annotations

from scytaledroid.StaticAnalysis.risk.permission import (
    ScoringParams,
    get_scoring_params,
    permission_points_0_20,
    permission_risk_grade,
    permission_risk_score,
    permission_risk_score_detail,
)

__all__ = [
    "ScoringParams",
    "get_scoring_params",
    "permission_points_0_20",
    "permission_risk_grade",
    "permission_risk_score",
    "permission_risk_score_detail",
]