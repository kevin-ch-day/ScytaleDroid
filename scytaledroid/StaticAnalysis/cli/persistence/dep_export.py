"""DEP JSON export helpers."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Config import app_config
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.version_utils import get_git_commit

from .dep_view import ensure_dep_view
from scytaledroid.Database.db_utils.artifact_registry import record_artifacts


_WATCH_PERMISSIONS = {
    "ACCESS_FINE_LOCATION": "location",
    "ACCESS_COARSE_LOCATION": "location",
    "ACCESS_BACKGROUND_LOCATION": "location",
    "READ_SMS": "sms",
    "RECEIVE_SMS": "sms",
    "SEND_SMS": "sms",
    "READ_CONTACTS": "contacts",
    "WRITE_CONTACTS": "contacts",
    "READ_PHONE_STATE": "phone_state",
    "RECORD_AUDIO": "microphone",
    "CAMERA": "camera",
    "SYSTEM_ALERT_WINDOW": "overlay",
}


def export_dep_json(static_run_id: int) -> str | None:
    if not ensure_dep_view():
        return None
    try:
        row = core_q.run_sql(
            "SELECT * FROM v_dep_static_profile WHERE static_run_id=%s",
            (static_run_id,),
            fetch="one",
        )
    except Exception as exc:
        log.warning(f"DEP view query failed for static_run_id={static_run_id}: {exc}", category="static_analysis")
        return None

    if not row:
        log.warning(f"DEP view returned no row for static_run_id={static_run_id}", category="static_analysis")
        return None

    columns = [
        "static_run_id",
        "package_name",
        "display_name",
        "profile_key",
        "version_code",
        "version_name",
        "min_sdk",
        "target_sdk",
        "session_stamp",
        "scope_label",
        "category",
        "profile",
        "sha256",
        "base_apk_sha256",
        "artifact_set_hash",
        "run_signature",
        "run_signature_version",
        "identity_valid",
        "identity_error_reason",
        "findings_total",
        "status",
        "ended_at_utc",
        "risk_score",
        "risk_grade",
        "risk_dangerous",
        "risk_signature",
        "risk_vendor",
        "exports_total",
        "masvs_total",
        "masvs_pass",
        "masvs_fail",
        "masvs_inconclusive",
        "dangerous_permissions",
        "signature_permissions",
        "custom_permissions",
        "permissions_total",
    ]
    payload = dict(zip(columns, row))

    package_name = payload.get("package_name") or "unknown"
    sha256 = payload.get("sha256") or payload.get("base_apk_sha256")
    artifact_token = str(sha256) if sha256 else f"run_{static_run_id}"
    evidence_dir = (
        Path("evidence")
        / "static_runs"
        / str(static_run_id)
        / str(package_name)
        / artifact_token
    )
    evidence_dir.mkdir(parents=True, exist_ok=True)

    watchlist = _build_watchlist(static_run_id)

    dep_payload: dict[str, Any] = {
        "schema": "dep_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "static_run_id": payload.get("static_run_id"),
        "package_name": package_name,
        "display_name": payload.get("display_name"),
        "profile_key": payload.get("profile_key"),
        "version_code": payload.get("version_code"),
        "version_name": payload.get("version_name"),
        "min_sdk": payload.get("min_sdk"),
        "target_sdk": payload.get("target_sdk"),
        "session_stamp": payload.get("session_stamp"),
        "scope_label": payload.get("scope_label"),
        "category": payload.get("category"),
        "profile": payload.get("profile"),
        "sha256": payload.get("sha256"),
        "base_apk_sha256": payload.get("base_apk_sha256"),
        "artifact_set_hash": payload.get("artifact_set_hash"),
        "run_signature": payload.get("run_signature"),
        "run_signature_version": payload.get("run_signature_version"),
        "identity_valid": payload.get("identity_valid"),
        "identity_error_reason": payload.get("identity_error_reason"),
        "findings_total": payload.get("findings_total"),
        "risk": {
            "score": payload.get("risk_score"),
            "grade": payload.get("risk_grade"),
            "dangerous": payload.get("risk_dangerous"),
            "signature": payload.get("risk_signature"),
            "vendor": payload.get("risk_vendor"),
        },
        "permissions": {
            "dangerous": payload.get("dangerous_permissions"),
            "signature": payload.get("signature_permissions"),
            "custom": payload.get("custom_permissions"),
            "total": payload.get("permissions_total"),
        },
        "components": {
            "exported_total": payload.get("exports_total"),
        },
        "masvs": {
            "total": payload.get("masvs_total"),
            "pass": payload.get("masvs_pass"),
            "fail": payload.get("masvs_fail"),
            "inconclusive": payload.get("masvs_inconclusive"),
        },
        "pcap_required": _derive_pcap_required(payload),
        "expected_background_activity": _derive_expected_background(payload),
        "watchlist": watchlist,
    }

    dep_path = evidence_dir / "dep.json"
    dep_path.write_text(json.dumps(dep_payload, indent=2, sort_keys=True))

    _write_static_manifest(static_run_id, dep_path, dep_payload)
    record_artifacts(
        run_id=str(static_run_id),
        run_type="static",
        artifacts=[_artifact_entry(dep_path, artifact_type="dep_snapshot")],
        origin="host",
        pull_status="n/a",
    )
    return str(dep_path)


def _write_static_manifest(
    static_run_id: int,
    dep_path: Path,
    dep_payload: Mapping[str, Any],
) -> None:
    package_name = dep_payload.get("package_name") or "unknown"
    schema_version = db_diagnostics.get_schema_version() or "<unknown>"
    manifest = {
        "run_manifest_version": 1,
        "static_run_id": static_run_id,
        "run_type": "static",
        "package_name": package_name,
        "display_name": dep_payload.get("display_name"),
        "version_code": dep_payload.get("version_code"),
        "version_name": dep_payload.get("version_name"),
        "session_stamp": dep_payload.get("session_stamp"),
        "scope_label": dep_payload.get("scope_label"),
        "category": dep_payload.get("category"),
        "profile": dep_payload.get("profile"),
        "profile_key": dep_payload.get("profile_key"),
        "schema_version": schema_version,
        "tool_semver": app_config.APP_VERSION,
        "tool_git_commit": get_git_commit(),
        "artifacts": [
            _artifact_entry(dep_path, artifact_type="dep_snapshot"),
        ],
    }
    manifest_path = dep_path.parent / "run_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))


def _artifact_entry(path: Path, *, artifact_type: str) -> Mapping[str, Any]:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "path": str(path),
        "type": artifact_type,
        "sha256": digest,
        "size_bytes": path.stat().st_size,
        "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _build_watchlist(static_run_id: int) -> Mapping[str, bool]:
    watchlist = {value: False for value in _WATCH_PERMISSIONS.values()}
    try:
        rows = core_q.run_sql(
            """
            SELECT permission_name
            FROM static_permission_matrix
            WHERE run_id=%s
            """,
            (static_run_id,),
            fetch="all",
        )
    except Exception:
        return watchlist

    if not rows:
        return watchlist
    for row in rows:
        if not row:
            continue
        name = str(row[0] or "").strip()
        if not name:
            continue
        token = name.split(".")[-1].upper()
        if token in _WATCH_PERMISSIONS:
            watchlist[_WATCH_PERMISSIONS[token]] = True
    return watchlist


def _derive_pcap_required(payload: Mapping[str, Any]) -> bool:
    grade = str(payload.get("risk_grade") or "").upper()
    if grade in {"HIGH", "CRITICAL"}:
        return True
    try:
        score = float(payload.get("risk_score") or 0.0)
        if score >= 50.0:
            return True
    except (TypeError, ValueError):
        pass
    return False


def _derive_expected_background(payload: Mapping[str, Any]) -> bool:
    try:
        exports_total = int(payload.get("exports_total") or 0)
        if exports_total > 0:
            return True
    except (TypeError, ValueError):
        pass
    return False


__all__ = ["export_dep_json"]
