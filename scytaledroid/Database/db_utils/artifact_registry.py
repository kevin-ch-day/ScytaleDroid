"""Artifact registry helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from scytaledroid.Database.db_core import db_queries as core_q


def record_artifacts(
    *,
    run_id: str,
    run_type: str,
    artifacts: Iterable[Mapping[str, Any]],
    origin: str = "host",
    base_path: Path | None = None,
    pull_status: str | None = None,
    status_reason: str | None = None,
) -> None:
    rows = []
    now = datetime.now(timezone.utc)
    for entry in artifacts:
        normalized = _normalize_artifact(entry, base_path)
        if not normalized:
            continue
        rows.append(
            (
                run_id,
                run_type,
                normalized.get("artifact_type"),
                origin,
                normalized.get("device_path"),
                normalized.get("host_path"),
                pull_status,
                normalized.get("sha256"),
                normalized.get("size_bytes"),
                normalized.get("created_at_utc") or now,
                normalized.get("pulled_at_utc"),
                status_reason,
                json.dumps(normalized.get("meta_json")) if normalized.get("meta_json") else None,
            )
        )
    if not rows:
        return
    sql = """
        INSERT INTO artifact_registry (
          run_id,
          run_type,
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
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
    return {
        "artifact_type": artifact_type,
        "host_path": host_path,
        "device_path": entry.get("device_path"),
        "sha256": sha256,
        "size_bytes": size_bytes,
        "created_at_utc": created_at,
        "pulled_at_utc": entry.get("pulled_at_utc"),
        "meta_json": entry.get("meta_json"),
    }


__all__ = ["record_artifacts"]
