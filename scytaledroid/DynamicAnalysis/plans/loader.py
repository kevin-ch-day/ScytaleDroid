"""Load and validate dynamic analysis plans."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, Iterable

from scytaledroid.Database.db_core import db_queries as core_q

SUPPORTED_SIGNATURE_VERSIONS = {"v1"}


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


def load_dynamic_plan(path: str | Path) -> Dict[str, Any]:
    plan_path = Path(path)
    data = json.loads(plan_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("dynamic plan payload must be an object")
    return data


def validate_dynamic_plan(
    plan: Dict[str, Any],
    *,
    package_name: str,
    static_run_id: int | None = None,
) -> PlanValidationOutcome:
    normalized_plan = _normalize_plan(plan)
    reasons: list[str] = []
    warnings: list[str] = []
    mismatches: list[dict[str, str]] = []

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
            required_fields=("run_signature", "run_signature_version", "artifact_set_hash"),
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


def _normalize_plan(plan: Dict[str, Any]) -> dict[str, object]:
    identity = plan.get("run_identity") if isinstance(plan.get("run_identity"), dict) else {}
    return {
        "package": plan.get("package_name") or plan.get("package"),
        "package_name": plan.get("package_name"),
        "static_run_id": plan.get("static_run_id"),
        "run_signature": plan.get("run_signature") or identity.get("run_signature"),
        "run_signature_version": plan.get("run_signature_version") or identity.get("run_signature_version"),
        "artifact_set_hash": plan.get("artifact_set_hash") or identity.get("artifact_set_hash"),
        "base_apk_sha256": plan.get("base_apk_sha256") or identity.get("base_apk_sha256"),
        "session_stamp": plan.get("session_stamp"),
    }


def extract_plan_identity(plan: Dict[str, Any]) -> dict[str, object]:
    """Expose normalized identity fields for plan selection."""
    return _normalize_plan(plan)


def _missing_required_fields(plan: dict[str, object]) -> list[str]:
    required = ("package", "static_run_id", "run_signature", "run_signature_version", "artifact_set_hash")
    missing = []
    for field in required:
        value = plan.get(field)
        if value is None or value == "":
            missing.append(field)
    return missing


def _missing_db_fields(row: dict[str, object]) -> list[str]:
    required = ("run_signature", "run_signature_version", "artifact_set_hash")
    return [field for field in required if not row.get(field)]


def _fetch_static_run_row(static_run_id: object | None) -> dict[str, object]:
    if static_run_id is None:
        return {}
    row = core_q.run_sql(
        """
        SELECT sar.id AS static_run_id,
               sar.run_signature,
               sar.run_signature_version,
               sar.artifact_set_hash,
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
    for field in required_fields:
        plan_value = plan.get(field)
        db_value = db.get(field)
        if plan_value is None or db_value is None:
            mismatches.append(
                _mismatch(
                    field,
                    expected=str(db_value or "missing"),
                    actual=str(plan_value or "missing"),
                )
            )
            continue
        if str(plan_value) != str(db_value):
            mismatches.append(_mismatch(field, expected=str(db_value), actual=str(plan_value)))
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
        "base_apk_sha256": _prefix(payload.get("base_apk_sha256") or "missing"),
        "pipeline_version": payload.get("pipeline_version"),
    }


__all__ = [
    "PlanValidationError",
    "PlanValidationOutcome",
    "SUPPORTED_SIGNATURE_VERSIONS",
    "extract_plan_identity",
    "build_plan_validation_event",
    "load_dynamic_plan",
    "render_plan_validation_block",
    "validate_dynamic_plan",
]
