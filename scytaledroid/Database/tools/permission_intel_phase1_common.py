"""Shared constants for Phase 1 permission-intel migration tooling."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_core.permission_intel import MANAGED_TABLES

DEFAULT_TARGET_DB = "android_permission_intel"

PHASE1_TABLES: tuple[str, ...] = MANAGED_TABLES


def write_phase1_artifact(
    path: str | Path,
    *,
    command: str,
    source_db: str,
    target_db: str,
    status: str,
    failed: bool,
    results: list[dict[str, Any]],
) -> Path:
    artifact_path = Path(path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "v1",
        "generated_at_utc": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "command": command,
        "source_db": source_db,
        "target_db": target_db,
        "status": status,
        "failed": bool(failed),
        "phase1_tables": list(PHASE1_TABLES),
        "results": results,
    }
    artifact_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return artifact_path


__all__ = ["DEFAULT_TARGET_DB", "PHASE1_TABLES", "write_phase1_artifact"]
