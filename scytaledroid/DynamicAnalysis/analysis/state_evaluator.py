"""Rule-based behavioral state evaluator for app-agnostic taxonomy."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

STATE_LABELS = (
    "idle",
    "heartbeat",
    "foreground_fetch",
    "media_streaming",
    "upload_publish",
    "background_sync",
    "telemetry_beacon",
    "update_fetch",
)


@dataclass(frozen=True)
class WindowFeatures:
    window_start: datetime
    window_end: datetime
    bytes_in: float
    bytes_out: float
    cpu_pct: float
    mem_kb: float
    burstiness: float
    duty_cycle: float
    periodicity: float
    uplink_ratio: float


@dataclass(frozen=True)
class EvidenceBundle:
    window_start: datetime
    window_end: datetime
    features_used: dict[str, float]
    cross_source_score: float
    reproducible: bool
    confidence: float
    rules_fired: list[str]


@dataclass(frozen=True)
class StateDecision:
    state: str
    confidence: float
    evidence: EvidenceBundle
    delta_conf: float


def evaluate_state(
    features: WindowFeatures,
    *,
    cross_source_score: float,
    reproducible: bool,
    confusion_threshold: float = 0.15,
) -> StateDecision:
    scores = _score_states(features)
    top_state, top_score = max(scores.items(), key=lambda item: item[1])
    sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    delta_conf = sorted_scores[0][1] - sorted_scores[1][1]
    state = top_state if delta_conf >= confusion_threshold else "uncertain"
    confidence = max(min(top_score, 1.0), 0.0)
    rules_fired = _rules_fired(features, top_state)
    evidence = EvidenceBundle(
        window_start=features.window_start,
        window_end=features.window_end,
        features_used={
            "bytes_in": features.bytes_in,
            "bytes_out": features.bytes_out,
            "cpu_pct": features.cpu_pct,
            "mem_kb": features.mem_kb,
            "burstiness": features.burstiness,
            "duty_cycle": features.duty_cycle,
            "periodicity": features.periodicity,
            "uplink_ratio": features.uplink_ratio,
        },
        cross_source_score=cross_source_score,
        reproducible=reproducible,
        confidence=confidence,
        rules_fired=rules_fired,
    )
    return StateDecision(state=state, confidence=confidence, evidence=evidence, delta_conf=delta_conf)


def _score_states(features: WindowFeatures) -> dict[str, float]:
    scores = {label: 0.0 for label in STATE_LABELS}
    total_bytes = features.bytes_in + features.bytes_out
    if total_bytes < 1024 and features.cpu_pct < 2.0:
        scores["idle"] += 0.9
    if features.periodicity > 0.7 and total_bytes < 10_000:
        scores["heartbeat"] += 0.8
    if features.bytes_in > features.bytes_out * 2 and features.burstiness > 0.4:
        scores["foreground_fetch"] += 0.7
    if features.duty_cycle > 0.7 and features.bytes_in > 50_000:
        scores["media_streaming"] += 0.8
    if features.uplink_ratio > 0.6 and features.cpu_pct > 10:
        scores["upload_publish"] += 0.75
    if features.duty_cycle < 0.3 and features.burstiness > 0.6:
        scores["background_sync"] += 0.65
    if features.periodicity > 0.5 and features.bytes_out < 5_000:
        scores["telemetry_beacon"] += 0.5
    if features.bytes_in > 200_000 and features.burstiness < 0.3:
        scores["update_fetch"] += 0.6
    return scores


def _rules_fired(features: WindowFeatures, state: str) -> list[str]:
    rules: list[str] = []
    if state == "idle":
        if features.bytes_in + features.bytes_out < 1024:
            rules.append("low_bytes")
        if features.cpu_pct < 2.0:
            rules.append("low_cpu")
    if state == "heartbeat" and features.periodicity > 0.7:
        rules.append("high_periodicity")
    if state == "foreground_fetch" and features.bytes_in > features.bytes_out * 2:
        rules.append("downlink_dominant")
    if state == "media_streaming" and features.duty_cycle > 0.7:
        rules.append("high_duty_cycle")
    if state == "upload_publish" and features.uplink_ratio > 0.6:
        rules.append("uplink_dominant")
    if state == "background_sync" and features.duty_cycle < 0.3:
        rules.append("low_duty_cycle")
    if state == "telemetry_beacon" and features.bytes_out < 5_000:
        rules.append("small_outbound")
    if state == "update_fetch" and features.bytes_in > 200_000:
        rules.append("large_download")
    return rules


def evaluate_windows(
    windows: Iterable[WindowFeatures],
    *,
    cross_source_score: float,
    reproducible: bool,
) -> list[StateDecision]:
    return [
        evaluate_state(window, cross_source_score=cross_source_score, reproducible=reproducible)
        for window in windows
    ]


__all__ = ["WindowFeatures", "EvidenceBundle", "StateDecision", "evaluate_state", "evaluate_windows"]
