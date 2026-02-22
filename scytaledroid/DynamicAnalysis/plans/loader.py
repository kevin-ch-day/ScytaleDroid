"""Load and validate dynamic analysis plans."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q

SUPPORTED_SIGNATURE_VERSIONS = {"v1"}
SUPPORTED_PLAN_SCHEMA_VERSIONS = {"v1"}


@dataclass(frozen=True)
class PlanValidationOutcome:
    status: str
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    mismatches: list[dict[str, str]] = field(default_factory=list)
    plan: dict[str, object] = field(default_factory=dict)
    db: dict[str, object] = field(default_factory=dict)
    source: str = "static_analysis_runs"

    @property
    def is_pass(self) -> bool:
        return self.status == "PASS"


class PlanValidationError(RuntimeError):
    def __init__(self, outcome: PlanValidationOutcome) -> None:
        super().__init__("dynamic plan validation failed")
        self.outcome = outcome


def load_dynamic_plan(path: str | Path) -> dict[str, Any]:
    plan_path = Path(path)
    data = json.loads(plan_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("dynamic plan payload must be an object")
    return _enrich_legacy_plan(data)


def enrich_dynamic_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Normalize/enrich plan payload for runtime/tooling use.

    Accepts already-loaded plan JSON and fills legacy gaps (identity/static_features)
    using deterministic fallbacks.
    """
    return _enrich_legacy_plan(plan)


def validate_dynamic_plan(
    plan: dict[str, Any],
    *,
    package_name: str,
    static_run_id: int | None = None,
) -> PlanValidationOutcome:
    normalized_plan = _normalize_plan(plan)
    reasons: list[str] = []
    warnings: list[str] = []
    mismatches: list[dict[str, str]] = []

    schema_issues = _plan_schema_issues(plan)
    if schema_issues:
        reasons.append(f"invalid plan schema: {', '.join(schema_issues)}")

    identity = plan.get("run_identity") if isinstance(plan.get("run_identity"), dict) else {}
    identity_valid = identity.get("identity_valid")
    if identity_valid is False:
        reasons.append("run_identity invalid (identity_valid=false)")

    missing_fields = _missing_required_fields(normalized_plan)
    if missing_fields:
        reasons.append(f"missing required fields: {', '.join(missing_fields)}")

    if normalized_plan.get("package") != package_name:
        mismatches.append(
            _mismatch(
                "package",
                expected=package_name,
                actual=str(normalized_plan.get("package") or "missing"),
            )
        )

    if static_run_id is not None:
        plan_run_id = normalized_plan.get("static_run_id")
        if plan_run_id is None:
            reasons.append("missing plan static_run_id")
        else:
            try:
                if int(plan_run_id) != int(static_run_id):
                    mismatches.append(
                        _mismatch("static_run_id", expected=str(static_run_id), actual=str(plan_run_id))
                    )
            except (TypeError, ValueError):
                reasons.append(f"invalid plan static_run_id: {plan_run_id}")

    signature_version = normalized_plan.get("run_signature_version")
    if signature_version not in SUPPORTED_SIGNATURE_VERSIONS:
        reasons.append(f"unsupported run_signature_version: {signature_version}")

    db_row = _fetch_static_run_row(normalized_plan.get("static_run_id"))
    if not db_row:
        reasons.append("static_run_id not found in static_analysis_runs")
        return _finalize_outcome(
            status="FAIL",
            reasons=reasons,
            warnings=warnings,
            mismatches=mismatches,
            plan=normalized_plan,
            db={},
        )

    db_missing = _missing_db_fields(db_row)
    if db_missing:
        reasons.append(f"static_analysis_runs missing fields: {', '.join(db_missing)}")

    if db_row.get("run_signature_version") not in SUPPORTED_SIGNATURE_VERSIONS:
        reasons.append(f"unsupported db run_signature_version: {db_row.get('run_signature_version')}")

    mismatches.extend(
        _compare_required_fields(
            normalized_plan,
            db_row,
            required_fields=("run_signature", "run_signature_version", "artifact_set_hash", "static_handoff_hash"),
        )
    )

    base_plan = normalized_plan.get("base_apk_sha256")
    base_db = db_row.get("base_apk_sha256")
    if base_plan and base_db and str(base_plan) != str(base_db):
        warnings.append("base_apk_sha256 mismatch")
    elif base_plan and not base_db:
        warnings.append("base_apk_sha256 missing in DB")
    elif base_db and not base_plan:
        warnings.append("base_apk_sha256 missing in plan")

    if normalized_plan.get("session_stamp") and normalized_plan.get("package"):
        link_check = _cross_check_session_link(
            normalized_plan["session_stamp"],
            normalized_plan["package"],
            normalized_plan.get("static_run_id"),
        )
        if link_check:
            reasons.append(link_check)

    status = "PASS"
    if reasons or mismatches:
        status = "FAIL"

    return _finalize_outcome(
        status=status,
        reasons=reasons,
        warnings=warnings,
        mismatches=mismatches,
        plan=normalized_plan,
        db=db_row,
    )


def render_plan_validation_block(outcome: PlanValidationOutcome) -> str:
    header = "PLAN VALIDATION"
    if outcome.status == "FAIL":
        header = "PLAN VALIDATION FAILED"
    lines = [header, "-" * len(header)]
    plan_package = outcome.plan.get("package") or "missing"
    plan_run_id = outcome.plan.get("static_run_id") or "missing"
    signature = _format_sig(outcome.plan.get("run_signature_version"), outcome.plan.get("run_signature"))
    lines.append(f"Package             : {plan_package}")
    lines.append(f"Static run          : {plan_run_id}")
    lines.append(f"Run signature       : {signature}")
    if outcome.db.get("artifact_set_hash"):
        hash_match = _match_marker(
            outcome.plan.get("artifact_set_hash"),
            outcome.db.get("artifact_set_hash"),
        )
        lines.append(f"Artifact set hash    : {hash_match}")
    if outcome.status == "PASS":
        if outcome.warnings:
            lines.append(f"Warnings             : {', '.join(outcome.warnings)}")
        lines.append("Validation result    : PASS")
        return "\n".join(lines)

    for reason in outcome.reasons:
        lines.append(f"Reason               : {reason}")
    for mismatch in outcome.mismatches:
        lines.append(f"Mismatch             : {mismatch['field']}")
        lines.append(f"Expected             : {mismatch['expected']}")
        lines.append(f"Plan                 : {mismatch['actual']}")
    lines.append("Dynamic execution blocked.")
    return "\n".join(lines)


def build_plan_validation_event(outcome: PlanValidationOutcome) -> dict[str, object]:
    return {
        "event": "plan.validation",
        "validation_result": outcome.status,
        "reasons": outcome.reasons,
        "warnings": outcome.warnings,
        "plan": _event_fields(outcome.plan),
        "db": _event_fields(outcome.db),
        "resolved_db_source": outcome.source,
    }


def _normalize_plan(plan: dict[str, Any]) -> dict[str, object]:
    identity = plan.get("run_identity") if isinstance(plan.get("run_identity"), dict) else {}
    return {
        "package": plan.get("package_name") or plan.get("package"),
        "package_name": plan.get("package_name"),
        # Back-compat: some plan writers store static_run_id only under run_identity.
        "static_run_id": plan.get("static_run_id") or identity.get("static_run_id"),
        "run_signature": plan.get("run_signature") or identity.get("run_signature"),
        "run_signature_version": plan.get("run_signature_version") or identity.get("run_signature_version"),
        "artifact_set_hash": plan.get("artifact_set_hash") or identity.get("artifact_set_hash"),
        "base_apk_sha256": plan.get("base_apk_sha256") or identity.get("base_apk_sha256"),
        "static_handoff_hash": plan.get("static_handoff_hash") or identity.get("static_handoff_hash"),
        "session_stamp": plan.get("session_stamp"),
    }


def extract_plan_identity(plan: dict[str, Any]) -> dict[str, object]:
    """Expose normalized identity fields for plan selection."""
    return _normalize_plan(plan)


def _as_bool(value: Any) -> bool | None:
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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _enrich_legacy_plan(plan: dict[str, Any]) -> dict[str, Any]:
    # Work on a copy to keep caller semantics predictable.
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

    run_sig = str(run_identity.get("run_signature") or "").strip().lower()
    signer_digest = str(run_identity.get("signer_digest") or "").strip().lower()
    signer_set_hash = str(run_identity.get("signer_set_hash") or "").strip().lower()
    if not signer_digest and len(run_sig) == 64:
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

    exported_total = _safe_int(
        static_features.get("exported_components_total"),
        _safe_int(exported.get("total"), 0),
    )
    dangerous_n = _safe_int(
        static_features.get("dangerous_permission_count"),
        len(dangerous),
    )
    cleartext_flag = _as_bool(
        static_features.get("uses_cleartext_traffic")
        if "uses_cleartext_traffic" in static_features
        else risk_flags.get("uses_cleartext_traffic")
    )
    if cleartext_flag is None:
        cleartext_flag = False
    sdk_score = _safe_float(
        static_features.get("sdk_indicator_score"),
        _safe_float(sdk_indicators.get("score"), 0.0),
    )
    sdk_score = max(0.0, min(1.0, sdk_score))

    # Legacy fallback risk scoring (same normalized structure used by static renderer).
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


def _missing_required_fields(plan: dict[str, object]) -> list[str]:
    required = (
        "package",
        "static_run_id",
        "run_signature",
        "run_signature_version",
        "artifact_set_hash",
        "static_handoff_hash",
    )
    missing = []
    for req_field in required:
        value = plan.get(req_field)
        if value is None or value == "":
            missing.append(req_field)
    return missing


def _plan_schema_issues(plan: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    # These keys must always exist for dataset-tier runs.
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


def _missing_db_fields(row: dict[str, object]) -> list[str]:
    required = ("run_signature", "run_signature_version", "artifact_set_hash", "static_handoff_hash")
    return [req_field for req_field in required if not row.get(req_field)]


def _fetch_static_run_row(static_run_id: object | None) -> dict[str, object]:
    if static_run_id is None:
        return {}
    row = core_q.run_sql(
        """
        SELECT sar.id AS static_run_id,
               sar.run_signature,
               sar.run_signature_version,
               sar.artifact_set_hash,
               sar.static_handoff_hash,
               sar.base_apk_sha256,
               sar.pipeline_version,
               a.package_name
        FROM static_analysis_runs sar
        LEFT JOIN app_versions av ON av.id = sar.app_version_id
        LEFT JOIN apps a ON a.id = av.app_id
        WHERE sar.id=%s
        """,
        (static_run_id,),
        fetch="one_dict",
    )
    if not isinstance(row, dict):
        return {}
    return row


def _cross_check_session_link(
    session_stamp: str,
    package_name: str,
    static_run_id: object | None,
) -> str | None:
    row = core_q.run_sql(
        """
        SELECT static_run_id
        FROM static_session_run_links
        WHERE session_stamp=%s AND package_name=%s
        LIMIT 1
        """,
        (session_stamp, package_name),
        fetch="one",
    )
    if not row:
        return None
    try:
        resolved = int(row[0])
        if static_run_id is not None and int(static_run_id) != resolved:
            return f"static_run_id mismatch vs session link (plan={static_run_id} link={resolved})"
    except (TypeError, ValueError):
        return "static_run_id invalid in session link"
    return None


def _compare_required_fields(
    plan: dict[str, object],
    db: dict[str, object],
    *,
    required_fields: Iterable[str],
) -> list[dict[str, str]]:
    mismatches: list[dict[str, str]] = []
    for req_field in required_fields:
        plan_value = plan.get(req_field)
        db_value = db.get(req_field)
        if plan_value is None or db_value is None:
            mismatches.append(
                _mismatch(
                    req_field,
                    expected=str(db_value or "missing"),
                    actual=str(plan_value or "missing"),
                )
            )
            continue
        if str(plan_value) != str(db_value):
            mismatches.append(
                _mismatch(req_field, expected=str(db_value), actual=str(plan_value))
            )
    return mismatches


def _mismatch(field: str, *, expected: str, actual: str) -> dict[str, str]:
    return {
        "field": field,
        "expected": _prefix(expected),
        "actual": _prefix(actual),
    }


def _prefix(value: object, *, length: int = 8) -> str:
    text = str(value)
    if len(text) <= length:
        return text
    return f"{text[:4]}…{text[-4:]}"


def _format_sig(version: object | None, signature: object | None) -> str:
    version_text = version or "missing"
    sig_text = _prefix(signature or "missing")
    return f"{version_text} / {sig_text}"


def _match_marker(plan_value: object, db_value: object) -> str:
    if plan_value is None or db_value is None:
        return "MISSING"
    if str(plan_value) == str(db_value):
        return "MATCH"
    return "MISMATCH"


def _finalize_outcome(
    *,
    status: str,
    reasons: list[str],
    warnings: list[str],
    mismatches: list[dict[str, str]],
    plan: dict[str, object],
    db: dict[str, object],
) -> PlanValidationOutcome:
    return PlanValidationOutcome(
        status=status,
        reasons=reasons,
        warnings=warnings,
        mismatches=mismatches,
        plan=plan,
        db=db,
    )


def _event_fields(payload: dict[str, object]) -> dict[str, object]:
    return {
        "package": payload.get("package"),
        "static_run_id": payload.get("static_run_id"),
        "run_signature": _prefix(payload.get("run_signature") or "missing"),
        "run_signature_version": payload.get("run_signature_version"),
        "artifact_set_hash": _prefix(payload.get("artifact_set_hash") or "missing"),
        "static_handoff_hash": _prefix(payload.get("static_handoff_hash") or "missing"),
        "base_apk_sha256": _prefix(payload.get("base_apk_sha256") or "missing"),
        "pipeline_version": payload.get("pipeline_version"),
    }


__all__ = [
    "PlanValidationError",
    "PlanValidationOutcome",
    "SUPPORTED_SIGNATURE_VERSIONS",
    "extract_plan_identity",
    "build_plan_validation_event",
    "enrich_dynamic_plan",
    "load_dynamic_plan",
    "render_plan_validation_block",
    "validate_dynamic_plan",
]
