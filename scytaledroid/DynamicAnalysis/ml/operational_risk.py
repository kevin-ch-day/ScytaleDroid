"""Operational (Phase F2) triage scoring and grading.

Important: this is not a Paper #2 claim. It is an operational, heuristic layer
intended to help practitioners prioritise review.

Terminology:
- Static axis: "Exposure" derived from static posture signals (capability).
  This is cohort-relative within a snapshot (min-max over selected groups).
- Dynamic axis: "Deviation" derived from anomaly prevalence and persistence.
- Final: rule-based posture regime (not a fused probabilistic score).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def exposure_grade(score_0_100: float | None) -> str:
    if score_0_100 is None:
        return "Unknown"
    s = float(score_0_100)
    if s >= 66.7:
        return "High"
    if s >= 33.4:
        return "Medium"
    return "Low"


def deviation_grade(
    *,
    anomalous_pct: float | None,
    longest_streak_seconds: float | None,
    confidence_level: str | None = None,
) -> str:
    """Grade deviation using prevalence and persistence; append confidence suffix when low."""
    if anomalous_pct is None and longest_streak_seconds is None:
        return "Unknown"
    p = float(anomalous_pct or 0.0)
    ls = float(longest_streak_seconds or 0.0)
    if p >= 0.20 or ls >= 60.0:
        base = "High"
    elif p >= 0.05 or ls >= 20.0:
        base = "Medium"
    else:
        base = "Low"
    conf = (confidence_level or "").strip().lower()
    if conf in {"low", "thin"}:
        return f"{base} (Low confidence)"
    return base


def confidence_modifier(confidence_level: str | None) -> float:
    c = (confidence_level or "").strip().lower()
    if c == "high":
        return 1.0
    if c == "medium":
        return 0.8
    if c == "low":
        return 0.6
    return 0.7


def dynamic_deviation_score_0_100(
    *,
    anomalous_pct: float | None,
    longest_streak_windows: int | None,
    windows_total: int | None,
    confidence_level: str | None,
) -> float | None:
    """Compute a simple 0-100 deviation score (operational heuristic).

    Components:
    - prevalence p in [0,1]
    - persistence L = longest_streak / total_windows in [0,1]
    - confidence downweight
    """
    if anomalous_pct is None or windows_total is None or windows_total <= 0:
        return None
    p = _clamp01(float(anomalous_pct))
    longest_frac = 0.0
    if longest_streak_windows is not None and windows_total > 0:
        longest_frac = _clamp01(float(max(int(longest_streak_windows), 0)) / float(int(windows_total)))
    raw = 0.7 * p + 0.3 * longest_frac
    mod = confidence_modifier(confidence_level)
    return float(round(100.0 * raw * mod, 3))


def final_posture_regime(
    *,
    exposure_grade_label: str,
    deviation_grade_label: str,
) -> str:
    """Rule-based regime label (paper-safe framing: capability vs deviation)."""
    e = (exposure_grade_label or "Unknown").split()[0]
    d = (deviation_grade_label or "Unknown").split()[0]
    if e == "Unknown" or d == "Unknown":
        return "Unknown"
    return f"{e} Exposure + {d} Deviation"


def final_posture_grade(
    *,
    exposure_grade_label: str,
    deviation_grade_label: str,
) -> str:
    """Map the 2D regime to an overall posture grade (Low/Medium/High)."""
    e = (exposure_grade_label or "Unknown").split()[0]
    d = (deviation_grade_label or "Unknown").split()[0]
    if e == "Unknown" or d == "Unknown":
        return "Unknown"
    if e == "Low" and d == "Low":
        return "Low"
    if e == "High" and d == "High":
        return "High"
    # Mixed cases default to Medium.
    return "Medium"


@dataclass(frozen=True)
class StaticPostureInputs:
    exported_components_total: int
    dangerous_permission_count: int
    uses_cleartext_traffic: int
    sdk_indicator_score: float


def static_exposure_score_components(
    *,
    E_norm: float | None,
    P_norm: float | None,
    C: int | None,
    S: float | None,
) -> float | None:
    """Paper-aligned exposure score computation on normalised components."""
    if E_norm is None or P_norm is None or C is None or S is None:
        return None
    e = _clamp01(float(E_norm))
    p = _clamp01(float(P_norm))
    c = 1.0 if int(C) else 0.0
    s = _clamp01(float(S))
    return float(round(100.0 * (0.25 * e + 0.25 * p + 0.25 * c + 0.25 * s), 3))


def minmax_norm(values: list[float]) -> list[float]:
    if not values:
        return []
    vmin = min(values)
    vmax = max(values)
    if (vmax - vmin) <= 1e-12:
        # Degenerate cohort (e.g., one app selected). Preserve "presence" signal rather
        # than forcing everything to 0.
        fill = 1.0 if vmax > 0.0 else 0.0
        return [float(fill) for _ in values]
    denom = float(vmax - vmin)
    return [float((v - vmin) / denom) for v in values]


def build_static_inputs_from_plan(plan: dict[str, Any]) -> StaticPostureInputs | None:
    if not isinstance(plan, dict):
        return None
    static_features = plan.get("static_features") if isinstance(plan.get("static_features"), dict) else {}
    exp = plan.get("exported_components") if isinstance(plan.get("exported_components"), dict) else {}
    perms = plan.get("permissions") if isinstance(plan.get("permissions"), dict) else {}
    rf = plan.get("risk_flags") if isinstance(plan.get("risk_flags"), dict) else {}
    try:
        exported_total = int(static_features.get("exported_components_total") or exp.get("total") or 0)
    except Exception:
        exported_total = 0
    try:
        dangerous_n = int(static_features.get("dangerous_permission_count"))
    except Exception:
        dangerous = perms.get("dangerous") if isinstance(perms.get("dangerous"), list) else []
        dangerous_n = int(len([p for p in dangerous if isinstance(p, str) and p.strip()]))
    cleartext_raw = static_features.get("uses_cleartext_traffic", rf.get("uses_cleartext_traffic"))
    uses_cleartext = 1 if cleartext_raw is True or cleartext_raw == 1 else 0
    sdk_score = 0.0
    if static_features.get("sdk_indicator_score") is not None:
        try:
            sdk_score = float(static_features.get("sdk_indicator_score") or 0.0)
        except Exception:
            sdk_score = 0.0
    sdk = plan.get("sdk_indicators")
    if sdk_score == 0.0 and isinstance(sdk, dict) and sdk.get("score") is not None:
        try:
            sdk_score = float(sdk.get("score") or 0.0)
        except Exception:
            sdk_score = 0.0
    return StaticPostureInputs(
        exported_components_total=exported_total,
        dangerous_permission_count=dangerous_n,
        uses_cleartext_traffic=uses_cleartext,
        sdk_indicator_score=sdk_score,
    )
