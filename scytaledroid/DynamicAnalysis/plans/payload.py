"""Payload loading, normalization, and legacy enrichment for dynamic plans."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scytaledroid.DeviceAnalysis.identity import normalize_hex_digest

from .models import SUPPORTED_PLAN_SCHEMA_VERSIONS


def load_dynamic_plan(path: str | Path) -> dict[str, Any]:
    plan_path = Path(path)
    data = json.loads(plan_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("dynamic plan payload must be an object")
    return enrich_dynamic_plan(data)


def enrich_dynamic_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Normalize/enrich plan payload for runtime/tooling use.

    Accepts already-loaded plan JSON and fills legacy gaps (identity/static_features)
    using deterministic fallbacks.
    """
    return _enrich_legacy_plan(plan)


def extract_plan_identity(plan: dict[str, Any]) -> dict[str, object]:
    """Expose normalized identity fields for plan selection."""
    return normalize_plan(plan)


def normalize_plan(plan: dict[str, Any]) -> dict[str, object]:
    identity = plan.get("run_identity") if isinstance(plan.get("run_identity"), dict) else {}
    return {
        "package": plan.get("package_name") or plan.get("package"),
        "package_name": plan.get("package_name"),
        "static_run_id": plan.get("static_run_id") or identity.get("static_run_id"),
        "apk_set_id": plan.get("apk_set_id") or identity.get("apk_set_id"),
        "run_signature": plan.get("run_signature") or identity.get("run_signature"),
        "run_signature_version": plan.get("run_signature_version") or identity.get("run_signature_version"),
        "artifact_set_hash": plan.get("artifact_set_hash") or identity.get("artifact_set_hash"),
        "base_apk_sha256": plan.get("base_apk_sha256") or identity.get("base_apk_sha256"),
        "static_handoff_hash": plan.get("static_handoff_hash") or identity.get("static_handoff_hash"),
        "session_stamp": plan.get("session_stamp"),
    }


def plan_schema_issues(plan: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    for key in ("plan_schema_version", "schema_version", "generated_at", "run_identity", "network_targets"):
        if key not in plan:
            issues.append(f"missing:{key}")
    schema_version = plan.get("plan_schema_version")
    if schema_version is not None and schema_version not in SUPPORTED_PLAN_SCHEMA_VERSIONS:
        issues.append(f"unsupported:plan_schema_version={schema_version}")
    identity = plan.get("run_identity")
    if "run_identity" in plan and not isinstance(identity, dict):
        issues.append("invalid:run_identity_not_object")
    if isinstance(identity, dict):
        for field in (
            "base_apk_sha256",
            "artifact_set_hash",
            "run_signature",
            "run_signature_version",
            "identity_valid",
            "identity_error_reason",
        ):
            if field not in identity:
                issues.append(f"missing:run_identity.{field}")
    network = plan.get("network_targets")
    if "network_targets" in plan and not isinstance(network, dict):
        issues.append("invalid:network_targets_not_object")
    if isinstance(network, dict):
        for field in ("domains", "cleartext_domains", "domain_sources", "domain_sources_note"):
            if field not in network:
                issues.append(f"missing:network_targets.{field}")
        for field in ("domains", "cleartext_domains", "domain_sources"):
            if field in network and not isinstance(network.get(field), list):
                issues.append(f"invalid:network_targets.{field}_not_array")
        if "domain_sources_note" in network and not isinstance(network.get("domain_sources_note"), str):
            issues.append("invalid:network_targets.domain_sources_note_not_string")
    return issues


def as_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y"}:
        return True
    if text in {"0", "false", "no", "n"}:
        return False
    return None


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _enrich_legacy_plan(plan: dict[str, Any]) -> dict[str, Any]:
    out = dict(plan)
    run_identity = out.get("run_identity") if isinstance(out.get("run_identity"), dict) else {}
    run_identity = dict(run_identity)

    package_name = str(out.get("package_name") or out.get("package") or "").strip()
    if package_name and not run_identity.get("package_name_lc"):
        run_identity["package_name_lc"] = package_name.lower()
    if out.get("version_code") not in (None, "") and run_identity.get("version_code") in (None, ""):
        run_identity["version_code"] = out.get("version_code")
    if out.get("version_name") not in (None, "") and run_identity.get("version_name") in (None, ""):
        run_identity["version_name"] = out.get("version_name")

    run_sig = normalize_hex_digest(run_identity.get("run_signature"))
    signer_digest = normalize_hex_digest(run_identity.get("signer_digest"))
    signer_set_hash = normalize_hex_digest(run_identity.get("signer_set_hash"))
    if not signer_digest and run_sig:
        signer_digest = run_sig
        run_identity["signer_digest"] = signer_digest
    if not signer_set_hash and signer_digest:
        run_identity["signer_set_hash"] = signer_digest
        signer_set_hash = signer_digest
    if signer_digest and not run_identity.get("signer_primary_digest"):
        run_identity["signer_primary_digest"] = signer_digest

    out["run_identity"] = run_identity

    static_features = out.get("static_features") if isinstance(out.get("static_features"), dict) else {}
    static_features = dict(static_features)
    perms = out.get("permissions") if isinstance(out.get("permissions"), dict) else {}
    declared = perms.get("declared") if isinstance(perms.get("declared"), list) else []
    dangerous = perms.get("dangerous") if isinstance(perms.get("dangerous"), list) else []
    high_value = perms.get("high_value") if isinstance(perms.get("high_value"), list) else []
    exported = out.get("exported_components") if isinstance(out.get("exported_components"), dict) else {}
    risk_flags = out.get("risk_flags") if isinstance(out.get("risk_flags"), dict) else {}
    sdk_indicators = out.get("sdk_indicators") if isinstance(out.get("sdk_indicators"), dict) else {}

    exported_total = safe_int(
        static_features.get("exported_components_total"),
        safe_int(exported.get("total"), 0),
    )
    dangerous_n = safe_int(
        static_features.get("dangerous_permission_count"),
        len(dangerous),
    )
    cleartext_flag = as_bool(
        static_features.get("uses_cleartext_traffic")
        if "uses_cleartext_traffic" in static_features
        else risk_flags.get("uses_cleartext_traffic")
    )
    if cleartext_flag is None:
        cleartext_flag = False
    sdk_score = safe_float(
        static_features.get("sdk_indicator_score"),
        safe_float(sdk_indicators.get("score"), 0.0),
    )
    sdk_score = max(0.0, min(1.0, sdk_score))

    exported_norm = min(float(exported_total) / 100.0, 1.0)
    dangerous_norm = min(float(dangerous_n) / 20.0, 1.0)
    cleartext_norm = 1.0 if cleartext_flag else 0.0
    static_risk_score = float(
        round(
            100.0
            * (
                (exported_norm * 0.25)
                + (dangerous_norm * 0.25)
                + (cleartext_norm * 0.25)
                + (sdk_score * 0.25)
            ),
            3,
        )
    )
    if static_risk_score >= 66.7:
        static_risk_band = "HIGH"
    elif static_risk_score >= 33.4:
        static_risk_band = "MEDIUM"
    else:
        static_risk_band = "LOW"

    static_features.setdefault("schema_version", "v1")
    static_features.setdefault("exported_components_total", int(exported_total))
    static_features.setdefault("dangerous_permission_count", int(dangerous_n))
    static_features.setdefault("permissions_total", int(len(declared)))
    static_features.setdefault("high_value_permission_count", int(len(high_value)))
    static_features.setdefault("high_value_permissions", list(high_value))
    static_features.setdefault("uses_cleartext_traffic", bool(cleartext_flag))
    static_features.setdefault("nsc_cleartext_permitted", bool(cleartext_flag))
    static_features.setdefault("nsc_cleartext_domain_count", len((out.get("network_targets") or {}).get("cleartext_domains") or []))
    static_features.setdefault("sdk_indicator_score", float(sdk_score))
    static_features.setdefault("perm_dangerous_n", int(dangerous_n))
    static_features.setdefault("masvs_total_score", None)
    static_features.setdefault("masvs_control_count_total", 0)
    static_features.setdefault("static_risk_score", float(static_risk_score))
    static_features.setdefault("static_risk_band", static_risk_band)
    static_features.setdefault(
        "masvs_area_counts",
        {
            "NETWORK": {"high": 0, "medium": 0, "low": 0, "info": 0, "control_count": 0},
            "PLATFORM": {"high": 0, "medium": 0, "low": 0, "info": 0, "control_count": 0},
            "PRIVACY": {"high": 0, "medium": 0, "low": 0, "info": 0, "control_count": 0},
            "STORAGE": {"high": 0, "medium": 0, "low": 0, "info": 0, "control_count": 0},
        },
    )
    out["static_features"] = static_features
    return out

