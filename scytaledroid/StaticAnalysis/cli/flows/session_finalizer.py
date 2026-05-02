"""Session-level finalization helpers for static analysis runs."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_utils.package_utils import resolve_package_identity
from scytaledroid.StaticAnalysis.cli.core.models import RunOutcome
from scytaledroid.Utils.DisplayUtils import status_messages


@dataclass(frozen=True)
class SessionFinalizationResult:
    """Summary of session-level finalization work."""

    run_map: dict | None = None
    links_written: int = 0
    cache_rows: int | None = None
    cache_materialized_at: object | None = None
    audit_path: str | None = None


def _row_field(row: Any, key: str, index: int = 0) -> Any:
    """Read a field from either a tuple-style or dict-style DB row."""

    if isinstance(row, dict):
        return row.get(key)
    if isinstance(row, (list, tuple)) and len(row) > index:
        return row[index]
    return None


def persist_static_session_links(
    session_stamp: str | None,
    run_map: dict | None,
    *,
    run_sql: Callable[..., Any],
    get_table_columns: Callable[[str], list[str] | None],
    write_query_name: str | None = None,
) -> SessionFinalizationResult:
    """Persist run-map linkage rows for a static session."""

    if not session_stamp or not run_map:
        return SessionFinalizationResult()

    columns = get_table_columns("static_session_run_links") or []
    static_ids = sorted(
        {
            int(app.get("static_run_id"))
            for app in run_map.get("apps", [])
            if isinstance(app, dict) and app.get("static_run_id") is not None
        }
    )
    if static_ids:
        rows = run_sql(
            f"SELECT id FROM static_analysis_runs WHERE id IN ({','.join(['%s'] * len(static_ids))})",
            tuple(static_ids),
            fetch="all",
        )
        existing = {
            int(value)
            for row in rows or []
            for value in [_row_field(row, "id")]
            if value is not None
        }
        missing_ids = [sid for sid in static_ids if sid not in existing]
        if missing_ids:
            raise RuntimeError(
                "static_session_run_links foreign key failure: "
                f"static_run_id(s) missing from static_analysis_runs: {', '.join(map(str, missing_ids))}"
            )

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    insert_columns = ["session_stamp", "package_name", "static_run_id"]
    if "run_origin" in columns:
        insert_columns.append("run_origin")
    if "origin_session_stamp" in columns:
        insert_columns.append("origin_session_stamp")
    if "pipeline_version" in columns:
        insert_columns.append("pipeline_version")
    if "base_apk_sha256" in columns:
        insert_columns.append("base_apk_sha256")
    if "artifact_set_hash" in columns:
        insert_columns.append("artifact_set_hash")
    if "run_signature" in columns:
        insert_columns.append("run_signature")
    if "run_signature_version" in columns:
        insert_columns.append("run_signature_version")
    if "identity_valid" in columns:
        insert_columns.append("identity_valid")
    if "identity_error_reason" in columns:
        insert_columns.append("identity_error_reason")
    if "linked_at_utc" in columns:
        insert_columns.append("linked_at_utc")
    placeholders = ", ".join(["%s"] * len(insert_columns))
    update_clause = ", ".join(
        f"{col}=VALUES({col})" for col in insert_columns if col not in {"session_stamp", "package_name"}
    )
    insert_sql = (
        "INSERT INTO static_session_run_links ("
        + ", ".join(insert_columns)
        + ") VALUES ("
        + placeholders
        + ")"
        + (" ON DUPLICATE KEY UPDATE " + update_clause if update_clause else "")
    )

    failures: list[str] = []
    inserted = 0
    for app in run_map.get("apps", []):
        if not isinstance(app, dict):
            continue
        package = str(app.get("package") or "").strip()
        static_run_id = app.get("static_run_id")
        if not package or not static_run_id:
            continue
        identity = resolve_package_identity(package, context="static_analysis")
        if not identity.normalized_package_name:
            failures.append(f"{package} (static_run_id={static_run_id}): invalid package identity")
            if len(failures) >= 3:
                break
            continue
        origin = app.get("run_origin") or "reused"
        origin_session = app.get("origin_session_stamp")
        pipeline_version = app.get("pipeline_version")
        base_apk_sha256 = app.get("base_apk_sha256")
        artifact_set_hash = app.get("artifact_set_hash")
        run_signature = app.get("run_signature")
        run_signature_version = app.get("run_signature_version")
        identity_valid = app.get("identity_valid")
        identity_error_reason = app.get("identity_error_reason")
        values: list[object] = [session_stamp, identity.normalized_package_name, int(static_run_id)]
        if "run_origin" in columns:
            values.append(origin)
        if "origin_session_stamp" in columns:
            values.append(origin_session)
        if "pipeline_version" in columns:
            values.append(pipeline_version)
        if "base_apk_sha256" in columns:
            values.append(base_apk_sha256)
        if "artifact_set_hash" in columns:
            values.append(artifact_set_hash)
        if "run_signature" in columns:
            values.append(run_signature)
        if "run_signature_version" in columns:
            values.append(run_signature_version)
        if "identity_valid" in columns:
            values.append(1 if identity_valid else 0 if identity_valid is not None else None)
        if "identity_error_reason" in columns:
            values.append(identity_error_reason)
        if "linked_at_utc" in columns:
            values.append(now)
        try:
            kwargs = {"query_name": write_query_name} if write_query_name else {}
            run_sql(insert_sql, tuple(values), **kwargs)
            inserted += 1
        except Exception as exc:
            failures.append(f"{identity.normalized_package_name} (static_run_id={static_run_id}): {exc}")
            if len(failures) >= 3:
                break
    if failures:
        raise RuntimeError(
            "static_session_run_links insert failed for "
            f"{len(failures)} row(s). First error: {failures[0]}"
        )
    return SessionFinalizationResult(links_written=inserted)


def finalize_session_run_map(
    outcome: RunOutcome | None,
    session_stamp: str | None,
    *,
    allow_overwrite: bool,
    required_fields: Sequence[str],
    build_session_run_map: Callable[..., dict | None],
    validate_run_map: Callable[[dict, str], None],
    persist_session_run_links_cb: Callable[[str | None, dict | None], None],
) -> SessionFinalizationResult:
    """Build, validate, and persist session linkage state in one place."""

    if not outcome or not session_stamp:
        return SessionFinalizationResult()

    run_map = build_session_run_map(
        outcome,
        session_stamp,
        allow_overwrite=bool(allow_overwrite),
    )
    if not run_map:
        return SessionFinalizationResult(run_map=None)

    _validate_required_run_map_fields(run_map, required_fields)
    validate_run_map(run_map, session_stamp)
    persist_session_run_links_cb(session_stamp, run_map)
    return SessionFinalizationResult(run_map=run_map)


def refresh_static_session_cache(
    *,
    refresh_cache: Callable[[], tuple[int, object]],
) -> SessionFinalizationResult:
    """Refresh the latest-package static/dynamic cache surface."""

    rows, materialized_at = refresh_cache()
    return SessionFinalizationResult(
        cache_rows=rows,
        cache_materialized_at=materialized_at,
    )


def emit_persistence_audit_artifact(
    *,
    outcome: RunOutcome,
    session_stamp: str | None,
    linkage_blocked_reason: str | None,
    missing_id_packages: list[str],
    db_schema_version: str,
    build_summary: Callable[[RunOutcome, str], dict[str, object]],
    lock_health_snapshot: Callable[..., object],
    output_dir: str | None = None,
) -> SessionFinalizationResult:
    """Emit the static persistence audit artifact for a session."""

    stamp = (session_stamp or "").strip() or "unspecified-session"
    missing_set = set(missing_id_packages)
    failure_lines = [
        str(line)
        for line in (
            list(getattr(outcome, "failures", []) or [])
            + list(getattr(outcome, "errors", []) or [])
        )
        if isinstance(line, str)
    ]

    def _failure_lines_for_package(package: str) -> list[str]:
        package_key = (package or "").strip().lower()
        if not package_key:
            return []
        return [line for line in failure_lines if package_key in line.lower()]

    def _extract_retry_count(lines: list[str]) -> int:
        max_retry = 0
        for line in lines:
            for pattern in (r"retry_count=(\d+)", r"retry=(\d+)", r"attempt=(\d+)"):
                for match in re.finditer(pattern, line, flags=re.IGNORECASE):
                    try:
                        max_retry = max(max_retry, int(match.group(1)))
                    except Exception:
                        continue
        return max_retry

    def _extract_errno(lines: list[str]) -> int | None:
        for line in lines:
            match = re.search(r"\((\d{4})\s*,", line)
            if match:
                try:
                    return int(match.group(1))
                except Exception:
                    pass
            match = re.search(r"errno=(\d{4})", line, flags=re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1))
                except Exception:
                    pass
        return None

    def _extract_transaction_state(lines: list[str]) -> str | None:
        for line in lines:
            match = re.search(r"transaction_state=([a-zA-Z_]+)", line, flags=re.IGNORECASE)
            if match:
                token = str(match.group(1) or "").strip().lower()
                if token:
                    return token
        return None

    def _looks_like_disconnect(lines: list[str]) -> bool:
        markers = ("2013", "2014", "lost connection", "server has gone away", "transientdberror")
        lowered = " ".join(lines).lower()
        return any(marker in lowered for marker in markers)

    def _looks_like_lock_wait(lines: list[str]) -> bool:
        markers = ("1205", "lock wait timeout", "deadlock")
        lowered = " ".join(lines).lower()
        return any(marker in lowered for marker in markers)

    def _classify_missing_run_id(app: object, package: str, package_failures: list[str]) -> str:
        identity_valid = getattr(app, "identity_valid", None)
        if identity_valid is False:
            return "identity_invalid"
        stage_hint = str(getattr(app, "persistence_failure_stage", "") or "").strip().lower()
        if stage_hint:
            if _looks_like_lock_wait(package_failures):
                return "db_lock_wait"
            return "db_write_failed"
        if _looks_like_lock_wait(package_failures):
            return "db_lock_wait"
        if int(getattr(app, "persistence_skipped", 0) or 0) > 0:
            return "persistence_skipped"
        if any("db_write_failed" in line.lower() for line in package_failures):
            return "db_write_failed"
        if any("persist" in line.lower() for line in package_failures):
            return "persist_error"
        if int(getattr(app, "failed_artifacts", 0) or 0) > 0:
            return "artifact_failed"
        if int(getattr(app, "persisted_artifacts", 0) or 0) == 0:
            return "not_persisted"
        return "missing_static_run_id"

    def _extract_stage(classification: str, package_failures: list[str]) -> str:
        for line in package_failures:
            if "db_write_failed:" in line:
                parts = line.split("db_write_failed:", 1)[1].split(":")
                token = (parts[0] if parts else "").strip()
                if token:
                    return token
        if classification in {"db_write_failed", "persist_error"}:
            return "persistence"
        if classification == "identity_invalid":
            return "identity_validation"
        return "unknown"

    rows: list[dict[str, object]] = []
    for app in outcome.results:
        package = str(getattr(app, "package_name", "") or "")
        static_run_id = getattr(app, "static_run_id", None)
        package_failures = _failure_lines_for_package(package)
        classification = "ok"
        if package in missing_set or static_run_id is None:
            classification = _classify_missing_run_id(app, package, package_failures)
        retry_count = int(getattr(app, "persistence_retry_count", 0) or 0)
        if retry_count <= 0:
            retry_count = _extract_retry_count(package_failures)
        errno = _extract_errno(package_failures)
        db_disconnect = bool(getattr(app, "persistence_db_disconnect", False))
        if not db_disconnect:
            db_disconnect = _looks_like_disconnect(package_failures)
        db_lock_wait = _looks_like_lock_wait(package_failures) or errno in {1205, 1213}
        tx_state = getattr(app, "persistence_transaction_state", None)
        if not tx_state:
            tx_state = _extract_transaction_state(package_failures)
        if not tx_state:
            tx_state = "unknown"
        exc_class = getattr(app, "persistence_exception_class", None)
        if not exc_class and db_disconnect:
            exc_class = "TransientDbError"
        stage = getattr(app, "persistence_failure_stage", None) or _extract_stage(
            classification, package_failures
        )
        if (not stage or stage == "unknown") and classification == "ok" and tx_state == "committed":
            stage = "completed"
        report_paths = [
            str(artifact.saved_path)
            for artifact in getattr(app, "artifacts", []) or []
            if getattr(artifact, "saved_path", None)
        ]
        base_artifact = app.base_artifact_outcome() if hasattr(app, "base_artifact_outcome") else None
        base_report_path = str(base_artifact.saved_path) if base_artifact and base_artifact.saved_path else None
        if base_report_path and "/archive/" in base_report_path:
            report_storage_mode = "archive"
        elif base_report_path and "/latest/" in base_report_path:
            report_storage_mode = "latest"
        elif base_report_path:
            report_storage_mode = "other"
        else:
            report_storage_mode = "missing"
        rows.append(
            {
                "package_name": package,
                "static_run_id": static_run_id,
                "missing_static_run_id": package in missing_set or static_run_id is None,
                "db_disconnect": db_disconnect,
                "db_lock_wait": bool(db_lock_wait),
                "errno": errno,
                "retry_count": retry_count,
                "classification": classification,
                "stage": stage,
                "exception_class": exc_class,
                "transaction_state": tx_state,
                "identity_error_reason": getattr(app, "identity_error_reason", None),
                "persisted_artifacts": int(getattr(app, "persisted_artifacts", 0) or 0),
                "failed_artifacts": int(getattr(app, "failed_artifacts", 0) or 0),
                "persistence_skipped": int(getattr(app, "persistence_skipped", 0) or 0),
                "artifact_reports": len(report_paths),
                "base_report_path": base_report_path,
                "report_storage_mode": report_storage_mode,
            }
        )

    missing_count = len([row for row in rows if row["missing_static_run_id"]])
    artifact_kind = "missing_run_ids" if missing_count else "persistence_audit"
    payload = {
        "schema_version": "v2",
        "db_schema_version": db_schema_version,
        "artifact_kind": artifact_kind,
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "session_stamp": stamp,
        "total_apps": len(outcome.results),
        "missing_static_run_id_count": missing_count,
        "linkage_blocked_reason": linkage_blocked_reason,
        "outcome": {
            "canonical_failed": bool(getattr(outcome, "canonical_failed", False)),
            "persistence_failed": bool(getattr(outcome, "persistence_failed", False)),
            "compat_export_failed": bool(getattr(outcome, "compat_export_failed", False)),
            "compat_export_stage": getattr(outcome, "compat_export_stage", None),
        },
        "summary": build_summary(outcome, stamp),
        "rows": rows,
    }

    out_root = Path(output_dir or app_config.OUTPUT_DIR) / "audit" / "persistence"
    out_root.mkdir(parents=True, exist_ok=True)
    suffix = "missing_run_ids" if missing_count else "persistence_audit"
    out_path = out_root / f"{stamp}_{suffix}.json"
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(status_messages.status(f"Persistence audit: {out_path}", level="info"))
    _emit_db_lock_health_artifact(stamp=stamp, rows=rows, lock_health_snapshot=lock_health_snapshot, out_root=out_root)
    return SessionFinalizationResult(audit_path=str(out_path))


def _emit_db_lock_health_artifact(
    *,
    stamp: str,
    rows: list[dict[str, object]],
    lock_health_snapshot: Callable[..., object],
    out_root: Path,
) -> None:
    should_emit = any(
        bool(row.get("missing_static_run_id"))
        or bool(row.get("db_lock_wait"))
        or str(row.get("classification") or "") in {"db_lock_wait", "db_write_failed"}
        for row in rows
    )
    if not should_emit:
        return
    snapshot = lock_health_snapshot(limit=25)
    out_path = out_root / f"{stamp}_db_lock_health.json"
    out_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
    print(status_messages.status(f"DB lock health: {out_path}", level="info"))


def _validate_required_run_map_fields(
    run_map: dict[str, Any],
    required_fields: Sequence[str],
) -> None:
    for entry in run_map.get("apps", []):
        missing = [
            field
            for field in ("static_run_id", *required_fields)
            if entry.get(field) in (None, "")
        ]
        if missing:
            raise RuntimeError(
                "run_map incomplete for package "
                f"{entry.get('package')}: missing {', '.join(missing)}"
            )


__all__ = [
    "SessionFinalizationResult",
    "emit_persistence_audit_artifact",
    "finalize_session_run_map",
    "persist_static_session_links",
    "refresh_static_session_cache",
]
