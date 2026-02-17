"""Permission risk persistence helpers."""

from __future__ import annotations

from collections.abc import Mapping

from scytaledroid.Database.db_utils.package_utils import normalize_package_name
from scytaledroid.Database.db_func.static_analysis import (
    risk_scores as risk_scores_db,
    static_permission_risk as permission_risk_db,
)

from .utils import canonical_decimal_text, first_text, require_canonical_schema

_RISK_SCORES_TABLE_READY = False
_PERMISSION_TABLE_VNEXT_READY = False


def _ensure_risk_scores_table() -> bool:
    global _RISK_SCORES_TABLE_READY
    if _RISK_SCORES_TABLE_READY:
        return True
    try:
        _RISK_SCORES_TABLE_READY = bool(risk_scores_db.ensure_table())
    except Exception as exc:  # pragma: no cover - defensive
        log.debug(
            "risk_scores table unavailable: %s",
            exc,
            category="static_analysis",
        )
        _RISK_SCORES_TABLE_READY = False
    return _RISK_SCORES_TABLE_READY


def _ensure_permission_vnext_table() -> bool:
    global _PERMISSION_TABLE_VNEXT_READY
    if _PERMISSION_TABLE_VNEXT_READY:
        return True
    try:
        _PERMISSION_TABLE_VNEXT_READY = bool(permission_risk_db.ensure_table_vnext())
    except Exception:
        _PERMISSION_TABLE_VNEXT_READY = False
    return _PERMISSION_TABLE_VNEXT_READY


def _risk_class_and_reason(profile: Mapping[str, object]) -> tuple[str | None, str | None]:
    guard_strength = str(profile.get("guard_strength") or "").strip().lower()
    runtime_dangerous = bool(profile.get("is_runtime_dangerous"))
    flagged_normal = bool(profile.get("is_flagged_normal"))
    if runtime_dangerous and guard_strength in {"weak", "unknown"}:
        return "HIGH", "RUNTIME_DANGEROUS_WEAK_GUARD"
    if runtime_dangerous:
        return "MEDIUM", "RUNTIME_DANGEROUS"
    if flagged_normal:
        return "LOW", "FLAGGED_NORMAL_PERMISSION"
    return None, None


def _persist_permission_risk_vnext(
    *,
    run_id: int,
    risk_score_text: str,
    permission_profiles: Mapping[str, Mapping[str, object]],
) -> None:
    if not _ensure_permission_vnext_table():
        raise RuntimeError("static_permission_risk_vnext table unavailable")
    seen_permission_names: set[str] = set()
    for permission_name, profile in permission_profiles.items():
        perm = str(permission_name or "").strip()
        if not perm:
            continue
        canonical_perm = perm.lower()
        if perm != canonical_perm:
            raise RuntimeError(
                f"PERSIST_VALIDATION_FAIL: permission_name must be canonical lowercase ({perm})"
            )
        if canonical_perm in seen_permission_names:
            raise RuntimeError(
                f"PERSIST_VALIDATION_FAIL: duplicate permission_name after canonicalization ({canonical_perm})"
            )
        seen_permission_names.add(canonical_perm)
        risk_class, rationale_code = _risk_class_and_reason(profile)
        permission_risk_db.upsert_vnext(
            {
                "run_id": int(run_id),
                "permission_name": canonical_perm,
                "risk_score": risk_score_text,
                "risk_class": risk_class,
                "rationale_code": rationale_code,
            }
        )


def persist_permission_risk(
    *,
    run_id: int | None,
    report: object,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    metrics_bundle: object,
    baseline_payload: Mapping[str, object],
    permission_profiles: Mapping[str, Mapping[str, object]] | None = None,
) -> None:
    if run_id is None:
        raise RuntimeError("permission_risk.write requires run_id")
    require_canonical_schema()
    _ = baseline_payload

    detail = getattr(metrics_bundle, "permission_detail", None)
    if not isinstance(detail, Mapping):
        detail = {}

    metadata_raw = getattr(report, "metadata", None)
    metadata = metadata_raw if isinstance(metadata_raw, Mapping) else {}
    package_name_lc = normalize_package_name(package_name, context="static_analysis")
    if not package_name_lc:
        raise RuntimeError("PERSIST_VALIDATION_FAIL: package_name missing")
    if not str(session_stamp or "").strip():
        raise RuntimeError("PERSIST_VALIDATION_FAIL: session_stamp missing")
    if not str(scope_label or "").strip():
        raise RuntimeError("PERSIST_VALIDATION_FAIL: scope_label missing")

    try:
        risk_score = canonical_decimal_text(
            getattr(metrics_bundle, "permission_score", detail.get("score_3dp", 0.0)),
            field="permissions.risk_score",
            scale=3,
            min_value=0.0,
            max_value=10.0,
        )
    except ValueError as exc:
        raise RuntimeError(f"PERSIST_VALIDATION_FAIL: {exc}") from exc
    risk_grade = first_text(
        getattr(metrics_bundle, "permission_grade", None),
        detail.get("grade"),
    ) or "A"

    if not _ensure_risk_scores_table():
        raise RuntimeError("risk_scores table unavailable")
    dangerous_count = int(getattr(metrics_bundle, "dangerous_permissions", detail.get("dangerous_count", 0)) or 0)
    signature_count = int(getattr(metrics_bundle, "signature_permissions", detail.get("signature_count", 0)) or 0)
    vendor_count = int(getattr(metrics_bundle, "oem_permissions", detail.get("oem_count", detail.get("vendor_count", 0))) or 0)
    try:
        risk_scores_db.upsert_risk(
            risk_scores_db.RiskScoreRecord(
                package_name=package_name_lc,
                app_label=first_text(
                    metadata.get("app_label"),
                    metadata.get("label"),
                ),
                session_stamp=session_stamp,
                scope_label=scope_label,
                risk_score=risk_score,
                risk_grade=risk_grade,
                dangerous=dangerous_count,
                signature=signature_count,
                vendor=vendor_count,
            )
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise RuntimeError(f"risk_scores upsert failed: {exc}") from exc

    profiles = permission_profiles if isinstance(permission_profiles, Mapping) else {}
    try:
        _persist_permission_risk_vnext(
            run_id=int(run_id),
            risk_score_text=str(risk_score),
            permission_profiles=profiles,
        )
    except Exception as exc:
        raise RuntimeError(f"static_permission_risk_vnext upsert failed: {exc}") from exc


__all__ = ["persist_permission_risk"]
