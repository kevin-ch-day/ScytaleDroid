"""Unified permission-risk scoring engine with contextual penalties."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.StaticAnalysis.modules.permissions.analysis.curves import (
    saturating_marginal,
    saturating_response,
)
from scytaledroid.StaticAnalysis.modules.permissions.analysis.name_patterns import (
    capture_group_count,
    health_group_count,
    is_background_sensitive_name,
    is_health_permission_name,
)

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
        "dangerous_cap": 6.50,
        "signature_cap": 2.80,
        "vendor_cap": 1.00,
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
        "background_sensitive_weight": 0.18,
        "background_sensitive_cap": 0.54,
        "health_sensitive_weight": 0.12,
        "health_sensitive_cap": 0.60,
        "privileged_declared_weight": 0.10,
        "privileged_declared_cap": 0.40,
    },
    "interactions": {
        "background_capture_scale": 0.35,
        "health_background_scale": 0.22,
    },
    "normalize": {"max_score": 10.0},
    "group_multipliers": {
        "camera": 1.0,
        "microphone": 1.0,
        "location": 1.0,
        "contacts": 1.0,
        "calendar": 1.0,
        "sms_mms": 1.0,
        "call_logs": 1.0,
        "storage_legacy": 1.0,
        "sensors_activity": 1.0,
        "health": 1.0,
        "notifications": 1.0,
        "bluetooth": 1.0,
        "nearby_devices": 1.0,
    },
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
        "interactions": dict(_DEFAULT_WEIGHTS["interactions"]),
        "normalize": dict(_DEFAULT_WEIGHTS["normalize"]),
        "group_multipliers": dict(_DEFAULT_WEIGHTS["group_multipliers"]),
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
                    if isinstance(data.get("interactions"), dict):
                        merged["interactions"].update(data.get("interactions") or {})
                    if isinstance(data.get("normalize"), dict):
                        merged["normalize"].update(data.get("normalize") or {})
                    if isinstance(data.get("group_multipliers"), dict):
                        merged["group_multipliers"].update(data.get("group_multipliers") or {})
                    _LOADED_WEIGHTS = merged  # type: ignore[assignment]
                    _LOADED_WEIGHTS_ENV_PATH = env_path
                    return _LOADED_WEIGHTS
        except Exception:
            continue

    _LOADED_WEIGHTS = merged
    _LOADED_WEIGHTS_ENV_PATH = env_path
    return _LOADED_WEIGHTS


_GROUP_MULTIPLIER_ALIASES = {
    "cam": "camera",
    "camera": "camera",
    "mic": "microphone",
    "microphone": "microphone",
    "loc": "location",
    "location": "location",
    "cnt": "contacts",
    "contacts": "contacts",
    "cal": "calendar",
    "calendar": "calendar",
    "sms": "sms_mms",
    "sms_mms": "sms_mms",
    "phn": "call_logs",
    "phone": "call_logs",
    "call_logs": "call_logs",
    "str": "storage_legacy",
    "storage_legacy": "storage_legacy",
    "sens": "health",
    "sensors": "sensors_activity",
    "sensors_activity": "sensors_activity",
    "health": "health",
    "act": "sensors_activity",
    "bt": "bluetooth",
    "bluetooth": "bluetooth",
    "not": "notifications",
    "notifications": "notifications",
    "nearby_devices": "nearby_devices",
}


def _group_multiplier(key: str, table: Mapping[str, Any] | None) -> float:
    alias = _GROUP_MULTIPLIER_ALIASES.get(str(key or "").strip().lower())
    if not alias or not isinstance(table, Mapping):
        return 1.0
    try:
        return max(0.0, float(table.get(alias, 1.0)))
    except (TypeError, ValueError):
        return 1.0


@dataclass(frozen=True)
class ScoringParams:
    dangerous_weight: float
    signature_weight: float
    vendor_weight: float
    dangerous_cap: float
    signature_cap: float
    vendor_cap: float
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
    background_sensitive_weight: float
    background_sensitive_cap: float
    health_sensitive_weight: float
    health_sensitive_cap: float
    privileged_declared_weight: float
    privileged_declared_cap: float
    background_capture_scale: float
    health_background_scale: float
    max_score: float


def get_scoring_params() -> ScoringParams:
    weights = _load_weights()
    base = weights.get("base", {}) if isinstance(weights, dict) else {}
    bonuses = weights.get("bonuses", {}) if isinstance(weights, dict) else {}
    penalties = weights.get("penalties", {}) if isinstance(weights, dict) else {}
    interactions = weights.get("interactions", {}) if isinstance(weights, dict) else {}
    normalize = weights.get("normalize", {}) if isinstance(weights, dict) else {}
    return ScoringParams(
        dangerous_weight=float(base.get("dangerous_weight", 0.0)),
        signature_weight=float(base.get("signature_weight", 0.0)),
        vendor_weight=float(base.get("vendor_weight", 0.0)),
        dangerous_cap=float(base.get("dangerous_cap", 0.0)),
        signature_cap=float(base.get("signature_cap", 0.0)),
        vendor_cap=float(base.get("vendor_cap", 1.0)),
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
        background_sensitive_weight=float(penalties.get("background_sensitive_weight", 0.0)),
        background_sensitive_cap=float(penalties.get("background_sensitive_cap", 0.0)),
        health_sensitive_weight=float(penalties.get("health_sensitive_weight", 0.0)),
        health_sensitive_cap=float(penalties.get("health_sensitive_cap", 0.0)),
        privileged_declared_weight=float(penalties.get("privileged_declared_weight", 0.0)),
        privileged_declared_cap=float(penalties.get("privileged_declared_cap", 0.0)),
        background_capture_scale=float(interactions.get("background_capture_scale", 0.0)),
        health_background_scale=float(interactions.get("health_background_scale", 0.0)),
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
    background_sensitive: int | None = None,
    health_sensitive: int | None = None,
    privileged_declared: int | None = None,
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
        background_sensitive=background_sensitive,
        health_sensitive=health_sensitive,
        privileged_declared=privileged_declared,
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
    background_sensitive: int | None = None,
    health_sensitive: int | None = None,
    privileged_declared: int | None = None,
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
        background_sensitive=background_sensitive,
        health_sensitive=health_sensitive,
        privileged_declared=privileged_declared,
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
    background_sensitive: int | None = None,
    health_sensitive: int | None = None,
    privileged_declared: int | None = None,
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
    dangerous_cap = float(base_w.get("dangerous_cap", 0.0))
    signature_cap = float(base_w.get("signature_cap", 0.0))
    vendor_cap = float(base_w.get("vendor_cap", 1.0))

    vendor_component_raw = v * vendor_weight
    vendor_component = saturating_response(v, vendor_weight, vendor_cap)
    dangerous_component = saturating_response(d, dangerous_weight, dangerous_cap)
    signature_component = saturating_response(s, signature_weight, signature_cap)
    base_components = {
        "dangerous": dangerous_component,
        "signature": signature_component,
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
    background_count = max(0, int(background_sensitive or 0))
    health_count = max(0, int(health_sensitive or 0))
    privileged_count = max(0, int(privileged_declared or 0))
    flagged_weight = float(penalties.get("flagged_normal_weight", 0.0))
    flagged_cap = float(penalties.get("flagged_normal_cap", 0.0))
    noteworthy_weight = float(penalties.get("noteworthy_normal_weight", flagged_weight))
    noteworthy_cap = float(penalties.get("noteworthy_normal_cap", flagged_cap))
    special_weight = float(penalties.get("special_risk_normal_weight", flagged_weight))
    special_cap = float(penalties.get("special_risk_normal_cap", flagged_cap))
    weak_weight = float(penalties.get("weak_guard_weight", 0.0))
    weak_cap = float(penalties.get("weak_guard_cap", 0.0))
    background_weight = float(penalties.get("background_sensitive_weight", 0.0))
    background_cap = float(penalties.get("background_sensitive_cap", 0.0))
    health_weight = float(penalties.get("health_sensitive_weight", 0.0))
    health_cap = float(penalties.get("health_sensitive_cap", 0.0))
    privileged_weight = float(penalties.get("privileged_declared_weight", 0.0))
    privileged_cap = float(penalties.get("privileged_declared_cap", 0.0))
    noteworthy_component = saturating_response(noteworthy_count, noteworthy_weight, noteworthy_cap)
    special_component = saturating_response(special_count, special_weight, special_cap)
    flagged_component = (
        noteworthy_component + special_component
        if using_split_flagged_normals
        else saturating_response(fn, flagged_weight, flagged_cap)
    )
    weak_guard_component = saturating_response(wg, weak_weight, weak_cap)
    background_component = saturating_response(background_count, background_weight, background_cap)
    health_component = saturating_response(health_count, health_weight, health_cap)
    privileged_component = saturating_response(privileged_count, privileged_weight, privileged_cap)
    penalty_components = {
        "flagged_normal": flagged_component,
        "noteworthy_normal": noteworthy_component,
        "special_risk_normal": special_component,
        "weak_guard": weak_guard_component,
        "background_sensitive": background_component,
        "health_sensitive": health_component,
        "privileged_declared": privileged_component,
    }

    interaction_cfg = weights.get("interactions", {}) if isinstance(weights, dict) else {}
    background_capture_scale = float(interaction_cfg.get("background_capture_scale", 0.0) or 0.0)
    health_background_scale = float(interaction_cfg.get("health_background_scale", 0.0) or 0.0)
    capture_groups = capture_group_count(groups)
    health_groups = health_group_count(groups)
    background_term = saturating_response(background_count, 1.0, 3.0) / 3.0
    capture_term = saturating_response(capture_groups, 1.0, 3.0) / 3.0
    health_term = saturating_response(health_count + health_groups, 1.0, 3.0) / 3.0
    background_capture_combo = background_capture_scale * background_term * capture_term
    health_background_combo = health_background_scale * background_term * health_term
    interaction_components = {
        "background_capture": background_capture_combo,
        "health_background": health_background_combo,
    }

    signal_subtotal = dangerous_component + signature_component + vendor_component
    base_total = signal_subtotal + sum(penalty_components.values()) + sum(interaction_components.values())

    breadth_step = float(bonuses.get("breadth_step", 0.2))
    breadth_cap = float(bonuses.get("breadth_cap", 2.0))
    group_multipliers = weights.get("group_multipliers", {}) if isinstance(weights, dict) else {}
    groups_present = 0
    weighted_groups = 0.0
    breadth = 0.0
    if groups:
        for key, value in groups.items():
            if int(value or 0) < 1:
                continue
            groups_present += 1
            weighted_groups += _group_multiplier(str(key), group_multipliers)
        breadth = saturating_response(weighted_groups, breadth_step, breadth_cap)

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
            "dangerous_cap": dangerous_cap,
            "signature_cap": signature_cap,
            "vendor_cap": vendor_cap,
            "breadth_step": breadth_step,
            "breadth_cap": breadth_cap,
            "response_curve": "saturating_exp",
            "token_combine": "cvss_iss_noisy_or",
        },
        "signal_components": base_components,
        "penalty_components": penalty_components,
        "interaction_components": interaction_components,
        "linear_reference": {
            "dangerous": d * dangerous_weight,
            "signature": s * signature_weight,
            "vendor": vendor_component_raw,
        },
        "signal_score_subtotal": base_total,
        "vendor_cap_applied": vendor_component != vendor_component_raw,
        "oem_cap_applied": vendor_component != vendor_component_raw,
        "breadth": {
            "groups_present": groups_present,
            "weighted_groups": round(weighted_groups, 4),
            "applied": breadth,
            "cap": breadth_cap,
        },
        "marginals": {
            "dangerous": saturating_marginal(d, dangerous_weight, dangerous_cap),
            "signature": saturating_marginal(s, signature_weight, signature_cap),
            "vendor": saturating_marginal(v, vendor_weight, vendor_cap),
            "background_sensitive": saturating_marginal(
                background_count, background_weight, background_cap
            ),
            "health_sensitive": saturating_marginal(health_count, health_weight, health_cap),
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
        "background_sensitive_count": background_count,
        "health_sensitive_count": health_count,
        "privileged_declared_count": privileged_count,
        "penalty_weights": {
            "flagged_normal_weight": flagged_weight,
            "flagged_normal_cap": flagged_cap,
            "noteworthy_normal_weight": noteworthy_weight,
            "noteworthy_normal_cap": noteworthy_cap,
            "special_risk_normal_weight": special_weight,
            "special_risk_normal_cap": special_cap,
            "weak_guard_weight": weak_weight,
            "weak_guard_cap": weak_cap,
            "background_sensitive_weight": background_weight,
            "background_sensitive_cap": background_cap,
            "health_sensitive_weight": health_weight,
            "health_sensitive_cap": health_cap,
            "privileged_declared_weight": privileged_weight,
            "privileged_declared_cap": privileged_cap,
        },
        "flagged_normal_component": flagged_component,
        "noteworthy_normal_component": noteworthy_component,
        "special_risk_normal_component": special_component,
        "weak_guard_component": weak_guard_component,
        "background_sensitive_component": background_component,
        "health_sensitive_component": health_component,
        "privileged_declared_component": privileged_component,
        "background_capture_combo": background_capture_combo,
        "health_background_combo": health_background_combo,
        "modernization_credit": modernization_credit,
        "using_split_flagged_normals": using_split_flagged_normals,
    }

    return rounded, detail


def collect_catalog_score_signals(
    profiles: Mapping[str, object] | None,
) -> dict[str, int]:
    """Count PI-backed sensitivity signals from permission profile payloads."""

    background_sensitive = 0
    health_sensitive = 0
    privileged_declared = 0
    for name, profile in (profiles or {}).items():
        if not isinstance(profile, Mapping):
            continue
        group = str(profile.get("group") or "").strip()
        if group.lower().startswith("android.permission-group."):
            group = group.rsplit(".", 1)[-1]
        if profile.get("background_permission") or is_background_sensitive_name(name):
            background_sensitive += 1
        if group.upper() == "HEALTH" or is_health_permission_name(name):
            health_sensitive += 1
        if profile.get("is_privileged"):
            privileged_declared += 1
    return {
        "background_sensitive": background_sensitive,
        "health_sensitive": health_sensitive,
        "privileged_declared": privileged_declared,
    }


__all__ = [
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
