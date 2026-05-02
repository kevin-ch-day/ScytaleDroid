"""Analysis-data overview helpers for DB health checks."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import run_sql


def count_evidence_integrity_issues(*, column_exists: Callable[[str, str], bool], scalar: Callable[..., object]) -> int:
    if column_exists("permission_audit_snapshots", "evidence_relpath"):
        missing_relpath = scalar(
            """
            SELECT COUNT(*)
            FROM permission_audit_snapshots
            WHERE evidence_relpath IS NULL OR evidence_relpath = ''
            """
        ) or 0
        missing_hash = scalar(
            """
            SELECT COUNT(*)
            FROM permission_audit_snapshots
            WHERE evidence_sha256 IS NULL OR evidence_sha256 = ''
            """
        ) or 0
        return int(missing_relpath) + int(missing_hash)
    return 0


def fetch_evidence_integrity_issues(limit: int = 25) -> list[dict[str, object]]:
    rows = run_sql(
        """
        SELECT snapshot_id, snapshot_key, run_id, static_run_id,
               (evidence_relpath IS NULL OR evidence_relpath='') AS missing_relpath,
               (evidence_sha256 IS NULL OR evidence_sha256='') AS missing_sha256
        FROM permission_audit_snapshots
        WHERE (evidence_relpath IS NULL OR evidence_relpath='')
           OR (evidence_sha256 IS NULL OR evidence_sha256='')
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (limit,),
        fetch="all",
        dictionary=True,
    )
    return rows or []


def load_feature_health_status() -> str | None:
    export_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1" / "analysis"
    json_path = export_dir / "feature_health.json"
    if not json_path.exists():
        return None
    try:
        payload = json.loads(json_path.read_text())
    except json.JSONDecodeError:
        return None
    status = payload.get("status")
    return status if isinstance(status, str) else None


def load_feature_health_report() -> dict[str, Any] | None:
    export_dir = Path(app_config.OUTPUT_DIR) / "exports" / "scytaledroid_dyn_v1" / "analysis"
    json_path = export_dir / "feature_health.json"
    if not json_path.exists():
        return None
    try:
        payload = json.loads(json_path.read_text())
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None
