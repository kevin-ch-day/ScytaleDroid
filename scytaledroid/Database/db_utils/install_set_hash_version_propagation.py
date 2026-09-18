"""Governed, fail-closed 0.3.17 install-set hash-version migration support.

This module intentionally does not infer versions for dynamic history.
"""
from __future__ import annotations
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

MIGRATION_ID = "20260918_install_set_hash_version_propagation_v1"
SCHEMA_VERSION_AFTER = "0.3.17-install-set-hash-version-propagation-v1"
VERSION_UNKNOWN_LEGACY = "VERSION_UNKNOWN_LEGACY"
IDENTITY_CONFLICT = "IDENTITY_CONFLICT"

DDL = (
    "ALTER TABLE static_analysis_runs ADD COLUMN IF NOT EXISTS artifact_set_hash_version VARCHAR(16) NULL",
    "ALTER TABLE dynamic_sessions ADD COLUMN IF NOT EXISTS artifact_set_hash_version VARCHAR(16) NULL",
    "CREATE INDEX IF NOT EXISTS ix_static_runs_artifact_set_identity ON static_analysis_runs (artifact_set_hash_version, artifact_set_hash)",
    "CREATE INDEX IF NOT EXISTS ix_dynamic_sessions_artifact_set_identity ON dynamic_sessions (artifact_set_hash_version, artifact_set_hash)",
)

@dataclass(frozen=True)
class StaticVersionDecision:
    run_id: int
    version: str | None
    classification: str

def decide_static_version(row: Mapping[str, Any]) -> StaticVersionDecision:
    run_id = int(row.get("id") or 0)
    run_hash = str(row.get("artifact_set_hash") or "").strip().lower()
    set_id = row.get("apk_set_id")
    set_hash = str(row.get("linked_artifact_set_hash") or "").strip().lower()
    version = str(row.get("linked_artifact_set_hash_version") or "").strip()
    if not set_id or not run_hash or not set_hash or not version:
        return StaticVersionDecision(run_id, None, VERSION_UNKNOWN_LEGACY)
    if run_hash != set_hash:
        return StaticVersionDecision(run_id, None, IDENTITY_CONFLICT)
    if version not in {"v1", "v2"}:
        return StaticVersionDecision(run_id, None, VERSION_UNKNOWN_LEGACY)
    return StaticVersionDecision(run_id, version, f"KNOWN_{version.upper()}")

def summarize_static_backfill(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    decisions = [decide_static_version(row) for row in rows]
    return {"static_total": len(decisions), "static_safe_candidates": sum(d.version is not None for d in decisions), "static_conflicts": sum(d.classification == IDENTITY_CONFLICT for d in decisions), "static_insufficient_proof": sum(d.classification == VERSION_UNKNOWN_LEGACY for d in decisions)}

def dynamic_legacy_classification(_: Mapping[str, Any]) -> str:
    return VERSION_UNKNOWN_LEGACY
