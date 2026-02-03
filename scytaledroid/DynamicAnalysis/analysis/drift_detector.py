"""Concept drift detection utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from scytaledroid.DynamicAnalysis.analysis.contrastive_testing import js_divergence, wasserstein_distance


@dataclass(frozen=True)
class DriftDecision:
    decision: str
    js_divergence: float
    wasserstein: float
    reasons: list[str]


def detect_drift(
    *,
    baseline_dist: Iterable[float],
    current_dist: Iterable[float],
    state_proportions_js: float,
    js_threshold: float = 0.1,
    wasserstein_threshold: float = 0.05,
) -> DriftDecision:
    js_value = js_divergence(baseline_dist, current_dist)
    w_value = wasserstein_distance(baseline_dist, current_dist)
    reasons: list[str] = []
    decision = "none"
    if js_value > js_threshold and w_value > wasserstein_threshold:
        decision = "sustained"
        reasons.append("distribution_shift")
    elif state_proportions_js > js_threshold:
        decision = "rebaseline_candidate"
        reasons.append("state_proportion_shift")
    if decision == "none" and js_value > js_threshold:
        decision = "anomaly_candidate"
        reasons.append("intermittent_shift")
    return DriftDecision(decision=decision, js_divergence=js_value, wasserstein=w_value, reasons=reasons)


__all__ = ["detect_drift", "DriftDecision"]
