"""Permission risk scoring helpers."""

from __future__ import annotations

from typing import Mapping, Any
from dataclasses import dataclass
from pathlib import Path
import os
import sys

try:  # Python 3.11+
    import tomllib as _toml
except Exception:  # pragma: no cover - very defensive
    _toml = None


_DEFAULT_WEIGHTS: dict[str, Any] = {
    # Calibrated to reduce saturation at the top end and provide
    # a clearer spread for Play-distributed apps.
    "base": {
        "dangerous_weight": 0.28,
        "signature_weight": 0.90,
        "vendor_weight": 0.04,
    },
    "bonuses": {
        # Breadth now contributes more gently and caps lower
        # so multi-capability apps do not immediately max out.
        "breadth_step": 0.12,
        "breadth_cap": 1.20,
    },
    "penalties": {
        # Treat risky normals and weak guard strengths as additive pressure
        # while keeping contributions bounded.
        "flagged_normal_weight": 0.18,
        "flagged_normal_cap": 1.20,
        "weak_guard_weight": 0.12,
        "weak_guard_cap": 0.80,
    },
    "normalize": {"max_score": 10.0},
}

_LOADED_WEIGHTS: dict[str, Any] | None = None


def _load_weights() -> dict[str, Any]:
    global _LOADED_WEIGHTS
    if _LOADED_WEIGHTS is not None:
        return _LOADED_WEIGHTS

    candidates = []
    env_path = os.environ.get("SCY_PERMISSION_RISK_TOML")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path("config/permission_risk.toml"))
    candidates.append(Path("data/config/permission_risk.toml"))

    merged = {
        "base": dict(_DEFAULT_WEIGHTS["base"]),
        "bonuses": dict(_DEFAULT_WEIGHTS["bonuses"]),
        "penalties": dict(_DEFAULT_WEIGHTS["penalties"]),
        "normalize": dict(_DEFAULT_WEIGHTS["normalize"]),
    }
    for path in candidates:
        try:
            if path.exists() and _toml is not None:
                with path.open("rb") as fh:
                    data = _toml.load(fh)
                # Only merge known keys if present
                if isinstance(data, dict) and data:
                    if isinstance(data.get("base"), dict):
                        merged["base"].update(data.get("base") or {})
                    if isinstance(data.get("bonuses"), dict):
                        merged["bonuses"].update(data.get("bonuses") or {})
                    if isinstance(data.get("penalties"), dict):
                        merged["penalties"].update(data.get("penalties") or {})
                    if isinstance(data.get("normalize"), dict):
                        merged["normalize"].update(data.get("normalize") or {})
                    _LOADED_WEIGHTS = merged  # type: ignore[assignment]
                    return _LOADED_WEIGHTS
        except Exception:
            continue

    _LOADED_WEIGHTS = merged
    return _LOADED_WEIGHTS


@dataclass(frozen=True)
class ScoringParams:
    dangerous_weight: float
    signature_weight: float
    vendor_weight: float
    breadth_step: float
    breadth_cap: float
    flagged_normal_weight: float
    flagged_normal_cap: float
    weak_guard_weight: float
    weak_guard_cap: float
    max_score: float


def get_scoring_params() -> ScoringParams:
    w = _load_weights()
    base = w.get("base", {}) if isinstance(w, dict) else {}
    bonuses = w.get("bonuses", {}) if isinstance(w, dict) else {}
    penalties = w.get("penalties", {}) if isinstance(w, dict) else {}
    normalize = w.get("normalize", {}) if isinstance(w, dict) else {}
    return ScoringParams(
        dangerous_weight=float(base.get("dangerous_weight", 0.0)),
        signature_weight=float(base.get("signature_weight", 0.0)),
        vendor_weight=float(base.get("vendor_weight", 0.0)),
        breadth_step=float(bonuses.get("breadth_step", 0.0)),
        breadth_cap=float(bonuses.get("breadth_cap", 0.0)),
        flagged_normal_weight=float(penalties.get("flagged_normal_weight", 0.0)),
        flagged_normal_cap=float(penalties.get("flagged_normal_cap", 0.0)),
        weak_guard_weight=float(penalties.get("weak_guard_weight", 0.0)),
        weak_guard_cap=float(penalties.get("weak_guard_cap", 0.0)),
        max_score=float(normalize.get("max_score", 10.0)),
    )


def permission_risk_score(
    *,
    dangerous: int,
    signature: int,
    vendor: int,
    groups: Mapping[str, int] | None = None,
    target_sdk: int | None = None,
    allow_backup: bool | None = None,
    legacy_external_storage: bool | None = None,
    flagged_normals: int | None = None,
    weak_guards: int | None = None,
) -> float:
    """Return a 0–10 risk score weighted for D/S and breadth.

    Modernization credit is applied when context is provided.
    """

    score, _ = _compute_score_detail(
        dangerous=dangerous,
        signature=signature,
        vendor=vendor,
        groups=groups,
        target_sdk=target_sdk,
        allow_backup=allow_backup,
        legacy_external_storage=legacy_external_storage,
        flagged_normals=flagged_normals,
        weak_guards=weak_guards,
    )
    return score


def permission_risk_score_detail(
    *,
    dangerous: int,
    signature: int,
    vendor: int,
    groups: Mapping[str, int] | None = None,
    target_sdk: int | None = None,
    allow_backup: bool | None = None,
    legacy_external_storage: bool | None = None,
    flagged_normals: int | None = None,
    weak_guards: int | None = None,
) -> Mapping[str, Any]:
    """Return the breakdown contributing to the permission risk score."""

    _, detail = _compute_score_detail(
        dangerous=dangerous,
        signature=signature,
        vendor=vendor,
        groups=groups,
        target_sdk=target_sdk,
        allow_backup=allow_backup,
        legacy_external_storage=legacy_external_storage,
        flagged_normals=flagged_normals,
        weak_guards=weak_guards,
    )
    return detail


def _compute_score_detail(
    *,
    dangerous: int,
    signature: int,
    vendor: int,
    groups: Mapping[str, int] | None = None,
    target_sdk: int | None = None,
    allow_backup: bool | None = None,
    legacy_external_storage: bool | None = None,
    flagged_normals: int | None = None,
    weak_guards: int | None = None,
) -> tuple[float, dict[str, Any]]:
    weights = _load_weights()
    base_w = weights.get("base", {}) if isinstance(weights, dict) else {}
    bonuses = weights.get("bonuses", {}) if isinstance(weights, dict) else {}
    penalties = weights.get("penalties", {}) if isinstance(weights, dict) else {}
    normalize = weights.get("normalize", {}) if isinstance(weights, dict) else {}

    d = max(0, int(dangerous))
    s = max(0, int(signature))
    v = max(0, int(vendor))

    dangerous_weight = float(base_w.get("dangerous_weight", 0.35))
    signature_weight = float(base_w.get("signature_weight", 1.25))
    vendor_weight = float(base_w.get("vendor_weight", 0.08))

    vendor_component_raw = v * vendor_weight
    # Keep vendor/ads modest and capped low to avoid dominating the score.
    vendor_component = min(1.0, vendor_component_raw)
    base_components = {
        "dangerous": d * dangerous_weight,
        "signature": s * signature_weight,
        "vendor": vendor_component,
    }

    fn = max(0, int(flagged_normals or 0))
    wg = max(0, int(weak_guards or 0))
    flagged_weight = float(penalties.get("flagged_normal_weight", 0.0))
    flagged_cap = float(penalties.get("flagged_normal_cap", 0.0))
    weak_weight = float(penalties.get("weak_guard_weight", 0.0))
    weak_cap = float(penalties.get("weak_guard_cap", 0.0))
    flagged_component = min(flagged_cap, fn * flagged_weight)
    weak_guard_component = min(weak_cap, wg * weak_weight)

    penalty_components = {
        "flagged_normal": flagged_component,
        "weak_guard": weak_guard_component,
    }

    base_total = sum(base_components.values()) + sum(penalty_components.values())

    breadth_step = float(bonuses.get("breadth_step", 0.2))
    breadth_cap = float(bonuses.get("breadth_cap", 2.0))
    groups_present = 0
    breadth = 0.0
    if groups:
        groups_present = sum(1 for val in groups.values() if val >= 1)
        breadth = min(breadth_cap, groups_present * breadth_step)

    # Modernization credit (max 0.8):
    # +0.3 if targetSdk>=34; +0.3 if legacy external storage is absent; +0.2 if allowBackup is false
    modernization_credit = 0.0
    try:
        if target_sdk is not None and int(target_sdk) >= 34:
            modernization_credit += 0.3
    except Exception:
        pass
    if legacy_external_storage is False:
        modernization_credit += 0.3
    if allow_backup is False:
        modernization_credit += 0.2
    modernization_credit = min(0.8, max(0.0, modernization_credit))

    raw_score = base_total + breadth - modernization_credit
    max_score = float(normalize.get("max_score", 10.0)) if isinstance(normalize, dict) else 10.0
    clamped = float(max(0.0, min(max_score, raw_score)))
    rounded = round(clamped, 3)

    detail: dict[str, Any] = {
        "weights_applied": {
            "dangerous": dangerous_weight,
            "signature": signature_weight,
            "vendor": vendor_weight,
            "breadth_step": breadth_step,
            "breadth_cap": breadth_cap,
        },
        "signal_components": base_components,
        "penalty_components": penalty_components,
        "signal_score_subtotal": base_total,
        "vendor_cap_applied": vendor_component != vendor_component_raw,
        "breadth": {
            "groups_present": groups_present,
            "applied": breadth,
            "cap": breadth_cap,
        },
        "score_raw": raw_score,
        "score_capped": clamped,
        "score_3dp": rounded,
        "dangerous_count": d,
        "signature_count": s,
        "vendor_count": v,
        "flagged_normal_count": fn,
        "weak_guard_count": wg,
        "penalty_weights": {
            "flagged_normal_weight": flagged_weight,
            "flagged_normal_cap": flagged_cap,
            "weak_guard_weight": weak_weight,
            "weak_guard_cap": weak_cap,
        },
        "flagged_normal_component": flagged_component,
        "weak_guard_component": weak_guard_component,
        "modernization_credit": modernization_credit,
    }

    return rounded, detail


def permission_points_0_20(score_0_10: float) -> float:
    """Map a 0–10 permission score to 0–20 points bucket."""
    try:
        s = float(score_0_10)
    except Exception:
        s = 0.0
    s = max(0.0, min(10.0, s))
    return round(s * 2.0, 2)


def permission_risk_grade(score: float) -> str:
    """Map a permission score to a letter grade (A–F) using fallback thresholds."""

    try:
        s = float(score)
    except (TypeError, ValueError):
        return "?"
    # Shift thresholds to widen distribution across A–D and reduce Fs.
    if s <= 2.0:
        return "A"
    if s <= 4.0:
        return "B"
    if s <= 6.5:
        return "C"
    if s <= 8.0:
        return "D"
    return "F"


__all__ = [
    "permission_risk_score",
    "permission_risk_score_detail",
    "permission_risk_grade",
    "permission_points_0_20",
    "ScoringParams",
    "get_scoring_params",
]
