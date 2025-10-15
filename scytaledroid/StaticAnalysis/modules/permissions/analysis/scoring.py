"""Permission risk scoring helpers."""

from __future__ import annotations

from typing import Mapping, Any
from pathlib import Path
import os
import sys

try:  # Python 3.11+
    import tomllib as _toml
except Exception:  # pragma: no cover - very defensive
    _toml = None


_DEFAULT_WEIGHTS: dict[str, Any] = {
    "base": {
        "dangerous_weight": 0.35,
        "signature_weight": 1.25,
        "vendor_weight": 0.08,
    },
    "bonuses": {
        "breadth_step": 0.2,
        "breadth_cap": 2.0,
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

    for path in candidates:
        try:
            if path.exists() and _toml is not None:
                with path.open("rb") as fh:
                    data = _toml.load(fh)
                if isinstance(data, dict) and data:
                    _LOADED_WEIGHTS = data  # type: ignore[assignment]
                    return _LOADED_WEIGHTS
        except Exception:
            continue

    _LOADED_WEIGHTS = _DEFAULT_WEIGHTS
    return _LOADED_WEIGHTS


def permission_risk_score(
    *,
    dangerous: int,
    signature: int,
    vendor: int,
    groups: Mapping[str, int] | None = None,
) -> float:
    """Return a 0–10 risk score weighted for D/S and breadth."""

    score, _ = _compute_score_detail(dangerous=dangerous, signature=signature, vendor=vendor, groups=groups)
    return score


def permission_risk_score_detail(
    *,
    dangerous: int,
    signature: int,
    vendor: int,
    groups: Mapping[str, int] | None = None,
) -> Mapping[str, Any]:
    """Return the breakdown contributing to the permission risk score."""

    _, detail = _compute_score_detail(dangerous=dangerous, signature=signature, vendor=vendor, groups=groups)
    return detail


def _compute_score_detail(
    *,
    dangerous: int,
    signature: int,
    vendor: int,
    groups: Mapping[str, int] | None = None,
) -> tuple[float, dict[str, Any]]:
    weights = _load_weights()
    base_w = weights.get("base", {}) if isinstance(weights, dict) else {}
    bonuses = weights.get("bonuses", {}) if isinstance(weights, dict) else {}
    normalize = weights.get("normalize", {}) if isinstance(weights, dict) else {}

    d = max(0, int(dangerous))
    s = max(0, int(signature))
    v = max(0, int(vendor))

    dangerous_weight = float(base_w.get("dangerous_weight", 0.35))
    signature_weight = float(base_w.get("signature_weight", 1.25))
    vendor_weight = float(base_w.get("vendor_weight", 0.08))

    vendor_component_raw = v * vendor_weight
    vendor_component = min(1.5, vendor_component_raw)
    base_components = {
        "dangerous": d * dangerous_weight,
        "signature": s * signature_weight,
        "vendor": vendor_component,
    }
    base_total = sum(base_components.values())

    breadth_step = float(bonuses.get("breadth_step", 0.2))
    breadth_cap = float(bonuses.get("breadth_cap", 2.0))
    groups_present = 0
    breadth = 0.0
    if groups:
        groups_present = sum(1 for val in groups.values() if val >= 1)
        breadth = min(breadth_cap, groups_present * breadth_step)

    raw_score = base_total + breadth
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
    }

    return rounded, detail


def permission_risk_grade(score: float) -> str:
    """Map a permission score to a letter grade (A–F) using fallback thresholds."""

    try:
        s = float(score)
    except (TypeError, ValueError):
        return "?"
    if s <= 3.0:
        return "A"
    if s <= 5.0:
        return "B"
    if s <= 7.0:
        return "C"
    if s <= 8.5:
        return "D"
    return "F"


__all__ = ["permission_risk_score", "permission_risk_score_detail", "permission_risk_grade"]
