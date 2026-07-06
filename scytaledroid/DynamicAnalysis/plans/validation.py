"""Dynamic plan validation against static-run persistence."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .db_lookup import cross_check_session_link, fetch_static_run_row, missing_db_fields
from .models import PlanValidationOutcome, SUPPORTED_SIGNATURE_VERSIONS
from .payload import normalize_plan, plan_schema_issues
from .rendering import mismatch


def validate_dynamic_plan(
    plan: dict[str, Any],
    *,
    package_name: str,
    static_run_id: int | None = None,
) -> PlanValidationOutcome:
    normalized_plan = normalize_plan(plan)
    reasons: list[str] = []
    warnings: list[str] = []
    mismatches: list[dict[str, str]] = []

    schema_issues = plan_schema_issues(plan)
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
            mismatch(
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
                        mismatch("static_run_id", expected=str(static_run_id), actual=str(plan_run_id))
                    )
            except (TypeError, ValueError):
                reasons.append(f"invalid plan static_run_id: {plan_run_id}")

    signature_version = normalized_plan.get("run_signature_version")
    if signature_version not in SUPPORTED_SIGNATURE_VERSIONS:
        reasons.append(f"unsupported run_signature_version: {signature_version}")

    db_row = fetch_static_run_row(normalized_plan.get("static_run_id"))
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

    db_missing = missing_db_fields(db_row)
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
        link_check = cross_check_session_link(
            normalized_plan["session_stamp"],
            normalized_plan["package"],
            normalized_plan.get("static_run_id"),
        )
        if link_check:
            reasons.append(link_check)

    status = "FAIL" if reasons or mismatches else "PASS"
    return _finalize_outcome(
        status=status,
        reasons=reasons,
        warnings=warnings,
        mismatches=mismatches,
        plan=normalized_plan,
        db=db_row,
    )


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
                mismatch(
                    req_field,
                    expected=str(db_value or "missing"),
                    actual=str(plan_value or "missing"),
                )
            )
            continue
        if str(plan_value) != str(db_value):
            mismatches.append(
                mismatch(req_field, expected=str(db_value), actual=str(plan_value))
            )
    return mismatches


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

