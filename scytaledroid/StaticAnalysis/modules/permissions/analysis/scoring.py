"""Tunable permission risk scoring helpers.

This isolates scoring math so we can iterate independently from renderers.
"""

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
    """Return a 0–10 risk score weighted for D/S and breadth.

    - Emphasize signature > dangerous, with small vendor contribution.
    - Add a modest breadth factor for apps touching many capability groups.
    - Clamp to [0, 10].
    """

    weights = _load_weights()
    base_w = weights.get("base", {}) if isinstance(weights, dict) else {}
    bonuses = weights.get("bonuses", {}) if isinstance(weights, dict) else {}
    d = max(0, dangerous)
    s = max(0, signature)
    v = max(0, vendor)

    base = (
        d * float(base_w.get("dangerous_weight", 0.35))
        + s * float(base_w.get("signature_weight", 1.25))
        + min(1.5, v * float(base_w.get("vendor_weight", 0.08)))
    )

    breadth = 0.0
    if groups:
        present = sum(1 for val in groups.values() if val >= 1)
        breadth_step = float(bonuses.get("breadth_step", 0.2))
        breadth_cap = float(bonuses.get("breadth_cap", 2.0))
        breadth = min(breadth_cap, present * breadth_step)

    score = base + breadth
    # Clamp then round to 3 decimals for display consistency
    max_score = float(weights.get("normalize", {}).get("max_score", 10.0)) if isinstance(weights, dict) else 10.0
    score = float(max(0.0, min(max_score, score)))
    return round(score, 3)


def permission_risk_grade(score: float) -> str:
    """Map a permission score to a letter grade (A–F) using fallback thresholds.

    Thresholds (inclusive):
    - A <= 3.0,
    - B <= 5.0,
    - C <= 7.0,
    - D <= 8.5,
    - F > 8.5
    """

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


__all__ = ["permission_risk_score", "permission_risk_grade"]
