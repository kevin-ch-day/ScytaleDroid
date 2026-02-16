"""Permission risk persistence helpers."""

from __future__ import annotations

import os
from collections.abc import Mapping

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.package_utils import normalize_package_name
from scytaledroid.Database.db_func.static_analysis import (
    risk_scores as risk_scores_db,
    static_permission_risk as permission_risk_db,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .utils import canonical_decimal_text, first_text, require_canonical_schema, safe_int

_PERMISSION_TABLE_READY = False
_RISK_SCORES_TABLE_READY = False
_PERMISSION_TABLE_VNEXT_READY = False


def _ensure_permission_table() -> bool:
    global _PERMISSION_TABLE_READY
    if _PERMISSION_TABLE_READY:
        return True
    try:
        permission_risk_db.ensure_table()
        _PERMISSION_TABLE_READY = True
    except Exception as exc:  # pragma: no cover - defensive
        log.debug(
            "Permission risk table unavailable: %s",
            exc,
            category="static_analysis",
        )
        _PERMISSION_TABLE_READY = False
    return _PERMISSION_TABLE_READY


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
        _PERMISSION_TABLE_VNEXT_READY = bool(permission_risk_db.table_exists_vnext())
    except Exception:
        _PERMISSION_TABLE_VNEXT_READY = False
    return _PERMISSION_TABLE_VNEXT_READY


def _vnext_enabled() -> bool:
    value = os.getenv("SCYTALEDROID_ENABLE_SPR_VNEXT", "0").strip().lower()
    return value in {"1", "true", "yes", "on"}


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
    for permission_name, profile in permission_profiles.items():
        perm = str(permission_name or "").strip()
        if not perm:
            continue
        risk_class, rationale_code = _risk_class_and_reason(profile)
        permission_risk_db.upsert_vnext(
            {
                "run_id": int(run_id),
                "permission_name": perm,
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
    if not _ensure_permission_table():
        raise RuntimeError("static_permission_risk table unavailable")
    require_canonical_schema()

    detail = getattr(metrics_bundle, "permission_detail", None)
    if not isinstance(detail, Mapping):
        detail = {}

    metadata_raw = getattr(report, "metadata", None)
    metadata = metadata_raw if isinstance(metadata_raw, Mapping) else {}
    apk_id = safe_int(metadata.get("apk_id")) or int(run_id)
    package_name_lc = normalize_package_name(package_name, context="static_analysis")
    if not package_name_lc:
        raise RuntimeError("PERSIST_VALIDATION_FAIL: package_name missing")
    if not str(session_stamp or "").strip():
        raise RuntimeError("PERSIST_VALIDATION_FAIL: session_stamp missing")
    if not str(scope_label or "").strip():
        raise RuntimeError("PERSIST_VALIDATION_FAIL: scope_label missing")

    sha256 = first_text(
        metadata.get("sha256"),
        metadata.get("hash_sha256"),
        metadata.get("SHA256"),
    )
    hashes_payload = getattr(report, "hashes", None)
    if isinstance(hashes_payload, Mapping) and not sha256:
        sha256 = first_text(
            hashes_payload.get("sha256"),
            hashes_payload.get("SHA256"),
            hashes_payload.get("sha-256"),
        )
    baseline_hashes = None
    if isinstance(baseline_payload, Mapping):
        baseline_hashes = baseline_payload.get("hashes")
        if not baseline_hashes and isinstance(baseline_payload.get("app"), Mapping):
            baseline_hashes = baseline_payload.get("app", {}).get("hashes")
    if isinstance(baseline_hashes, Mapping) and not sha256:
        sha256 = first_text(
            baseline_hashes.get("sha256"),
            baseline_hashes.get("SHA256"),
            baseline_hashes.get("sha-256"),
        )
    if not sha256:
        try:
            row = core_q.run_sql(
                "SELECT sha256 FROM static_analysis_runs WHERE id=%s",
                (run_id,),
                fetch="one",
            )
            if row and row[0]:
                sha256 = first_text(row[0])
        except Exception:
            sha256 = None
    if not sha256 and run_id is not None:
        sha256 = f"run-{run_id}"
    if not sha256:
        log.debug(f"Skipping permission risk persistence for {package_name}: missing sha256", category="static_analysis")
        return

    app_id: int | None = None
    try:
        row = core_q.run_sql(
            "SELECT av.app_id FROM static_analysis_runs r JOIN app_versions av ON av.id = r.app_version_id WHERE r.id = %s",
            (run_id,),
            fetch="one",
        )
        if row and row[0]:
            app_id = safe_int(row[0])
    except Exception:
        app_id = None

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

    payload = {
        "apk_id": int(apk_id),
        "app_id": app_id,
        "package_name": package_name_lc,
        "sha256": sha256,
        "session_stamp": session_stamp,
        "scope_label": scope_label,
        "risk_score": risk_score,
        "risk_grade": risk_grade,
        "dangerous": int(getattr(metrics_bundle, "dangerous_permissions", detail.get("dangerous_count", 0)) or 0),
        "signature": int(getattr(metrics_bundle, "signature_permissions", detail.get("signature_count", 0)) or 0),
        "vendor": int(getattr(metrics_bundle, "oem_permissions", detail.get("oem_count", detail.get("vendor_count", 0))) or 0),
    }

    try:
        permission_risk_db.upsert(payload)
    except Exception as exc:  # pragma: no cover - defensive
        raise RuntimeError(f"static_permission_risk upsert failed: {exc}") from exc

    if not _ensure_risk_scores_table():
        raise RuntimeError("risk_scores table unavailable")
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
                dangerous=int(payload["dangerous"]),
                signature=int(payload["signature"]),
                vendor=int(payload["vendor"]),
            )
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise RuntimeError(f"risk_scores upsert failed: {exc}") from exc

    if _vnext_enabled():
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
