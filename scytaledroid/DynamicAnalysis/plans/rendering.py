"""Rendering helpers for dynamic plan validation results."""

from __future__ import annotations

from .models import PlanValidationOutcome


def plan_validation_pass_message(run_profile: str | None) -> str:
    profile = str(run_profile or "").strip().lower()
    if profile.startswith("baseline"):
        return "Plan validation: PASS (baseline shown above)."
    if profile.startswith("interaction"):
        return "Plan validation: PASS (selected app/build shown above)."
    return "Plan validation: PASS (selected plan shown above)."


def render_plan_validation_block(outcome: PlanValidationOutcome) -> str:
    header = "PLAN VALIDATION"
    if outcome.status == "FAIL":
        header = "PLAN VALIDATION FAILED"
    lines = [header, "-" * len(header)]
    plan_package = outcome.plan.get("package") or "missing"
    plan_run_id = outcome.plan.get("static_run_id") or "missing"
    signature = format_sig(outcome.plan.get("run_signature_version"), outcome.plan.get("run_signature"))
    lines.append(f"Package             : {plan_package}")
    lines.append(f"Static run          : {plan_run_id}")
    lines.append(f"Run signature       : {signature}")
    if outcome.db.get("artifact_set_hash"):
        hash_match = match_marker(
            outcome.plan.get("artifact_set_hash"),
            outcome.db.get("artifact_set_hash"),
        )
        lines.append(f"Artifact set hash    : {hash_match}")
    if outcome.db.get("static_handoff_hash"):
        handoff_match = match_marker(
            outcome.plan.get("static_handoff_hash"),
            outcome.db.get("static_handoff_hash"),
        )
        lines.append(f"Static handoff hash  : {handoff_match}")
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
        "summary": {
            "reason_count": len(outcome.reasons),
            "warning_count": len(outcome.warnings),
            "mismatch_count": len(outcome.mismatches),
            "db_row_found": bool(outcome.db),
            "has_static_link": bool(
                outcome.plan.get("artifact_set_hash")
                and outcome.plan.get("static_handoff_hash")
                and outcome.plan.get("run_signature")
            ),
        },
        "plan": event_fields(outcome.plan),
        "db": event_fields(outcome.db),
        "resolved_db_source": outcome.source,
    }


def mismatch(field: str, *, expected: str, actual: str) -> dict[str, str]:
    return {
        "field": field,
        "expected": prefix(expected),
        "actual": prefix(actual),
    }


def prefix(value: object, *, length: int = 8) -> str:
    text = str(value)
    if len(text) <= length:
        return text
    return f"{text[:4]}…{text[-4:]}"


def format_sig(version: object | None, signature: object | None) -> str:
    version_text = version or "missing"
    sig_text = prefix(signature or "missing")
    return f"{version_text} / {sig_text}"


def match_marker(plan_value: object, db_value: object) -> str:
    if plan_value is None or db_value is None:
        return "MISSING"
    if str(plan_value) == str(db_value):
        return "MATCH"
    return "MISMATCH"


def event_fields(payload: dict[str, object]) -> dict[str, object]:
    return {
        "package": payload.get("package"),
        "static_run_id": payload.get("static_run_id"),
        "run_signature": prefix(payload.get("run_signature") or "missing"),
        "run_signature_version": payload.get("run_signature_version"),
        "artifact_set_hash": prefix(payload.get("artifact_set_hash") or "missing"),
        "static_handoff_hash": prefix(payload.get("static_handoff_hash") or "missing"),
        "base_apk_sha256": prefix(payload.get("base_apk_sha256") or "missing"),
        "pipeline_version": payload.get("pipeline_version"),
    }


__all__ = [
    "build_plan_validation_event",
    "plan_validation_pass_message",
    "render_plan_validation_block",
]
