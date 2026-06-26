"""Artifact registry helpers."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def normalize_dynamic_run_uuid(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text or not _UUID_RE.match(text):
        return None
    return text.lower()


def resolve_typed_linkage(
    *,
    run_id: str,
    run_type: str,
    static_run_id: int | None = None,
    dynamic_run_id: str | None = None,
    linkage_migration_status: str | None = None,
) -> tuple[int | None, str | None, str]:
    """Return typed linkage fields for ``artifact_registry`` writes.

    New writes should populate typed linkage eagerly while preserving legacy
    ``run_id`` for backward compatibility.
    """

    rt = str(run_type or "").strip().lower()
    run_id_text = str(run_id or "").strip()
    resolved_static = int(static_run_id) if static_run_id is not None else None
    resolved_dynamic = str(dynamic_run_id).strip() if dynamic_run_id is not None else None
    status = str(linkage_migration_status or "").strip() or "legacy_unclassified"

    if rt == "static":
        if resolved_static is None and run_id_text.isdigit():
            resolved_static = int(run_id_text)
        if resolved_static is not None and status == "legacy_unclassified":
            status = "typed_static_writer"
    elif rt == "dynamic":
        if not resolved_dynamic and run_id_text:
            resolved_dynamic = run_id_text
        if resolved_dynamic and status == "legacy_unclassified":
            status = "typed_dynamic_writer"

    return resolved_static, resolved_dynamic, status


def record_artifacts(
    *,
    run_id: str,
    run_type: str,
    artifacts: Iterable[Mapping[str, Any]],
    session_stamp: str | None = None,
    origin: str = "host",
    base_path: Path | None = None,
    pull_status: str | None = None,
    status_reason: str | None = None,
    static_run_id: int | None = None,
    dynamic_run_id: str | None = None,
    linkage_migration_status: str | None = None,
) -> None:
    rows = []
    now = datetime.now(UTC)
    typed_static_run_id, typed_dynamic_run_id, typed_status = resolve_typed_linkage(
        run_id=run_id,
        run_type=run_type,
        static_run_id=static_run_id,
        dynamic_run_id=dynamic_run_id,
        linkage_migration_status=linkage_migration_status,
    )
    dynamic_run_uuid = normalize_dynamic_run_uuid(typed_dynamic_run_id)
    resolved_session_stamp = str(session_stamp or "").strip() or None
    for entry in artifacts:
        normalized = _normalize_artifact(entry, base_path)
        if not normalized:
            continue
        entry_origin = normalized.get("origin") or origin
        entry_pull_status = normalized.get("pull_status") or pull_status
        entry_status_reason = normalized.get("status_reason") or status_reason
        created_at = _coerce_datetime(normalized.get("created_at_utc")) or now
        pulled_at = _coerce_datetime(normalized.get("pulled_at_utc"))
        rows.append(
            (
                run_id,
                run_type,
                resolved_session_stamp,
                typed_static_run_id,
                typed_dynamic_run_id,
                dynamic_run_uuid,
                typed_status,
                normalized.get("artifact_type"),
                entry_origin,
                normalized.get("device_path"),
                normalized.get("host_path"),
                entry_pull_status,
                normalized.get("sha256"),
                normalized.get("size_bytes"),
                _format_datetime(created_at),
                _format_datetime(pulled_at) if pulled_at else None,
                entry_status_reason,
                json.dumps(normalized.get("meta_json")) if normalized.get("meta_json") else None,
            )
        )
    if not rows:
        return
    sql = """
        INSERT INTO artifact_registry (
          run_id,
          run_type,
          session_stamp,
          static_run_id,
          dynamic_run_id,
          dynamic_run_uuid,
          linkage_migration_status,
          artifact_type,
          origin,
          device_path,
          host_path,
          pull_status,
          sha256,
          size_bytes,
          created_at_utc,
          pulled_at_utc,
          status_reason,
          meta_json
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    core_q.run_sql_many(sql, rows, query_name="artifact_registry.insert")


def _normalize_artifact(entry: Mapping[str, Any], base_path: Path | None) -> Mapping[str, Any] | None:
    if not isinstance(entry, Mapping):
        return None
    artifact_type = entry.get("type") or entry.get("artifact_type")
    if not artifact_type:
        return None
    rel_path = entry.get("relative_path") or entry.get("path")
    host_path = None
    if rel_path and base_path:
        host_path = str((base_path / rel_path).resolve())
    elif rel_path:
        host_path = str(Path(str(rel_path)).resolve())
    size_bytes = entry.get("size_bytes")
    sha256 = entry.get("sha256")
    created_at = entry.get("created_at_utc")
    origin = entry.get("origin")
    device_path = entry.get("device_path")
    if origin is None and device_path:
        origin = "device"
    pull_status = entry.get("pull_status")
    if pull_status is None and origin == "device":
        pull_status = "pending"
    if origin is None and not device_path:
        origin = "unknown"
        if pull_status is None:
            pull_status = "unknown"
    return {
        "artifact_type": artifact_type,
        "host_path": host_path,
        "device_path": device_path,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "created_at_utc": created_at,
        "pulled_at_utc": entry.get("pulled_at_utc"),
        "meta_json": entry.get("meta_json"),
        "origin": origin,
        "pull_status": pull_status,
        "status_reason": entry.get("status_reason")
        or ("manifest_missing_device_path" if origin == "unknown" else None),
    }


def _coerce_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text.replace("Z", "+00:00")
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _format_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


__all__ = ["normalize_dynamic_run_uuid", "record_artifacts", "resolve_typed_linkage"]
