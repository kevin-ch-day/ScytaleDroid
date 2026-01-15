"""Permission risk persistence helpers."""

from __future__ import annotations

from typing import Mapping, Optional

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_func.static_analysis import static_permission_risk as permission_risk_db
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .utils import first_text, safe_int

_PERMISSION_TABLE_READY = False


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


def persist_permission_risk(
    *,
    run_id: int | None,
    report: object,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    metrics_bundle: object,
    baseline_payload: Mapping[str, object],
) -> None:
    if run_id is None or not _ensure_permission_table():
        return

    detail = getattr(metrics_bundle, "permission_detail", None)
    if not isinstance(detail, Mapping):
        detail = {}

    metadata_raw = getattr(report, "metadata", None)
    metadata = metadata_raw if isinstance(metadata_raw, Mapping) else {}
    apk_id = safe_int(metadata.get("apk_id")) or int(run_id)

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

    app_id: Optional[int] = None
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

    risk_score = float(getattr(metrics_bundle, "permission_score", detail.get("score_3dp", 0.0)) or 0.0)
    risk_grade = first_text(
        getattr(metrics_bundle, "permission_grade", None),
        detail.get("grade"),
    ) or "A"

    payload = {
        "apk_id": int(apk_id),
        "app_id": app_id,
        "package_name": package_name,
        "sha256": sha256,
        "session_stamp": session_stamp,
        "scope_label": scope_label,
        "risk_score": risk_score,
        "risk_grade": risk_grade,
        "dangerous": int(getattr(metrics_bundle, "dangerous_permissions", detail.get("dangerous_count", 0)) or 0),
        "signature": int(getattr(metrics_bundle, "signature_permissions", detail.get("signature_count", 0)) or 0),
        "vendor": int(getattr(metrics_bundle, "vendor_permissions", detail.get("vendor_count", 0)) or 0),
    }

    try:
        permission_risk_db.upsert(payload)
    except Exception as exc:  # pragma: no cover - defensive
        log.debug(
            f"Permission risk upsert skipped for {package_name}: {exc}",
            category="static_analysis",
        )


__all__ = ["persist_permission_risk"]
