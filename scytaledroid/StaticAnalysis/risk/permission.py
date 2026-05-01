"""Unified permission-risk scoring engine with contextual penalties."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib as _toml
except Exception:  # pragma: no cover
    try:  # pragma: no cover
        import tomli as _toml  # type: ignore[no-redef]
    except Exception:  # pragma: no cover
        _toml = None


_DEFAULT_WEIGHTS: dict[str, Any] = {
    "base": {
        "dangerous_weight": 0.22,
        "signature_weight": 0.55,
        "vendor_weight": 0.02,
    },
    "bonuses": {
        "breadth_step": 0.08,
        "breadth_cap": 0.80,
    },
    "penalties": {
        "flagged_normal_weight": 0.10,
        "flagged_normal_cap": 0.60,
        "noteworthy_normal_weight": 0.06,
        "noteworthy_normal_cap": 0.24,
        "special_risk_normal_weight": 0.16,
        "special_risk_normal_cap": 0.60,
        "weak_guard_weight": 0.08,
        "weak_guard_cap": 0.50,
    },
    "normalize": {"max_score": 10.0},
}

_LOADED_WEIGHTS: dict[str, Any] | None = None
_LOADED_WEIGHTS_ENV_PATH: str | None = None


def _load_weights() -> dict[str, Any]:
    global _LOADED_WEIGHTS, _LOADED_WEIGHTS_ENV_PATH
    env_path = os.environ.get("SCY_PERMISSION_RISK_TOML")
    if _LOADED_WEIGHTS is not None and _LOADED_WEIGHTS_ENV_PATH == env_path:
        return _LOADED_WEIGHTS

    candidates = []
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
                    _LOADED_WEIGHTS_ENV_PATH = env_path
                    return _LOADED_WEIGHTS
        except Exception:
            continue

    _LOADED_WEIGHTS = merged
    _LOADED_WEIGHTS_ENV_PATH = env_path
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
    noteworthy_normal_weight: float
    noteworthy_normal_cap: float
    special_risk_normal_weight: float
    special_risk_normal_cap: float
    weak_guard_weight: float
    weak_guard_cap: float
    max_score: float


def get_scoring_params() -> ScoringParams:
    weights = _load_weights()
    base = weights.get("base", {}) if isinstance(weights, dict) else {}
    bonuses = weights.get("bonuses", {}) if isinstance(weights, dict) else {}
    penalties = weights.get("penalties", {}) if isinstance(weights, dict) else {}
    normalize = weights.get("normalize", {}) if isinstance(weights, dict) else {}
    return ScoringParams(
        dangerous_weight=float(base.get("dangerous_weight", 0.0)),
        signature_weight=float(base.get("signature_weight", 0.0)),
        vendor_weight=float(base.get("vendor_weight", 0.0)),
        breadth_step=float(bonuses.get("breadth_step", 0.0)),
        breadth_cap=float(bonuses.get("breadth_cap", 0.0)),
        flagged_normal_weight=float(penalties.get("flagged_normal_weight", 0.0)),
        flagged_normal_cap=float(penalties.get("flagged_normal_cap", 0.0)),
        noteworthy_normal_weight=float(penalties.get("noteworthy_normal_weight", penalties.get("flagged_normal_weight", 0.0))),
        noteworthy_normal_cap=float(penalties.get("noteworthy_normal_cap", penalties.get("flagged_normal_cap", 0.0))),
        special_risk_normal_weight=float(penalties.get("special_risk_normal_weight", penalties.get("flagged_normal_weight", 0.0))),
        special_risk_normal_cap=float(penalties.get("special_risk_normal_cap", penalties.get("flagged_normal_cap", 0.0))),
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
    noteworthy_normals: int | None = None,
    special_risk_normals: int | None = None,
    weak_guards: int | None = None,
) -> float:
    score, _ = _compute_score_detail(
        dangerous=dangerous,
        signature=signature,
        vendor=vendor,
        groups=groups,
        target_sdk=target_sdk,
        allow_backup=allow_backup,
        legacy_external_storage=legacy_external_storage,
        flagged_normals=flagged_normals,
        noteworthy_normals=noteworthy_normals,
        special_risk_normals=special_risk_normals,
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
    noteworthy_normals: int | None = None,
    special_risk_normals: int | None = None,
    weak_guards: int | None = None,
) -> Mapping[str, Any]:
    _, detail = _compute_score_detail(
        dangerous=dangerous,
        signature=signature,
        vendor=vendor,
        groups=groups,
        target_sdk=target_sdk,
        allow_backup=allow_backup,
        legacy_external_storage=legacy_external_storage,
        flagged_normals=flagged_normals,
        noteworthy_normals=noteworthy_normals,
        special_risk_normals=special_risk_normals,
        weak_guards=weak_guards,
    )
    return detail


def permission_points_0_20(score_0_10: float) -> float:
    try:
        s = float(score_0_10)
    except Exception:
        s = 0.0
    s = max(0.0, min(10.0, s))
    return round(s * 2.0, 2)


def permission_risk_grade(score: float) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "?"
    if s <= 2.0:
        return "A"
    if s <= 4.0:
        return "B"
    if s <= 6.5:
        return "C"
    if s <= 8.0:
        return "D"
    return "F"


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
    noteworthy_normals: int | None = None,
    special_risk_normals: int | None = None,
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
    vendor_component = min(1.0, vendor_component_raw)
    base_components = {
        "dangerous": d * dangerous_weight,
        "signature": s * signature_weight,
        "vendor": vendor_component,
        "oem": vendor_component,
    }

    fn = max(0, int(flagged_normals or 0))
    noteworthy_fn = noteworthy_normals
    special_fn = special_risk_normals
    using_split_flagged_normals = noteworthy_fn is not None or special_fn is not None
    noteworthy_count = max(0, int(noteworthy_fn or 0))
    special_count = max(0, int(special_fn or 0))
    if not using_split_flagged_normals:
        noteworthy_count = fn
        special_count = 0
    wg = max(0, int(weak_guards or 0))
    flagged_weight = float(penalties.get("flagged_normal_weight", 0.0))
    flagged_cap = float(penalties.get("flagged_normal_cap", 0.0))
    noteworthy_weight = float(penalties.get("noteworthy_normal_weight", flagged_weight))
    noteworthy_cap = float(penalties.get("noteworthy_normal_cap", flagged_cap))
    special_weight = float(penalties.get("special_risk_normal_weight", flagged_weight))
    special_cap = float(penalties.get("special_risk_normal_cap", flagged_cap))
    weak_weight = float(penalties.get("weak_guard_weight", 0.0))
    weak_cap = float(penalties.get("weak_guard_cap", 0.0))
    noteworthy_component = min(noteworthy_cap, noteworthy_count * noteworthy_weight)
    special_component = min(special_cap, special_count * special_weight)
    flagged_component = (
        noteworthy_component + special_component
        if using_split_flagged_normals
        else min(flagged_cap, fn * flagged_weight)
    )
    weak_guard_component = min(weak_cap, wg * weak_weight)
    penalty_components = {
        "flagged_normal": flagged_component,
        "noteworthy_normal": noteworthy_component,
        "special_risk_normal": special_component,
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
            "oem": vendor_weight,
            "breadth_step": breadth_step,
            "breadth_cap": breadth_cap,
        },
        "signal_components": base_components,
        "penalty_components": penalty_components,
        "signal_score_subtotal": base_total,
        "vendor_cap_applied": vendor_component != vendor_component_raw,
        "oem_cap_applied": vendor_component != vendor_component_raw,
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
        "oem_count": v,
        "flagged_normal_count": fn,
        "noteworthy_normal_count": noteworthy_count,
        "special_risk_normal_count": special_count,
        "weak_guard_count": wg,
        "penalty_weights": {
            "flagged_normal_weight": flagged_weight,
            "flagged_normal_cap": flagged_cap,
            "noteworthy_normal_weight": noteworthy_weight,
            "noteworthy_normal_cap": noteworthy_cap,
            "special_risk_normal_weight": special_weight,
            "special_risk_normal_cap": special_cap,
            "weak_guard_weight": weak_weight,
            "weak_guard_cap": weak_cap,
        },
        "flagged_normal_component": flagged_component,
        "noteworthy_normal_component": noteworthy_component,
        "special_risk_normal_component": special_component,
        "weak_guard_component": weak_guard_component,
        "modernization_credit": modernization_credit,
        "using_split_flagged_normals": using_split_flagged_normals,
    }

    return rounded, detail


__all__ = [
    "ScoringParams",
    "get_scoring_params",
    "permission_points_0_20",
    "permission_risk_grade",
    "permission_risk_score",
    "permission_risk_score_detail",
]
