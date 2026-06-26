"""Additive session-stamp support for ``artifact_registry``."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .schema_migration_registry import (
    MigrationSpec,
    append_schema_version,
    latest_schema_version,
    record_schema_migration,
)

RunSql = Callable[..., Any]
RunSqlRowcount = Callable[..., int]

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RECEIPT_SUBDIR = "artifact_registry_session_stamp"
MIGRATION_ID = "20260625_artifact_registry_session_stamp_v1"
SCHEMA_VERSION_AFTER = "0.3.12-artifact-registry-session-stamp"

ARTIFACT_REGISTRY_SESSION_MIGRATION = MigrationSpec(
    migration_id=MIGRATION_ID,
    migration_name="Artifact registry session-stamp additive support",
    schema_version_before="0.3.11-dynamic-service-signals",
    schema_version_after=SCHEMA_VERSION_AFTER,
    statements=(
        "ALTER TABLE artifact_registry ADD COLUMN IF NOT EXISTS session_stamp VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL",
        "CREATE INDEX IF NOT EXISTS ix_artifact_session_stamp ON artifact_registry (session_stamp)",
        "CREATE INDEX IF NOT EXISTS ix_artifact_run_type_session_created ON artifact_registry (run_type, session_stamp, created_at_utc)",
    ),
    description="Adds optional session_stamp to artifact_registry so static session-scoped audit and cleanup can avoid extra recovery joins.",
    apply_mode="manual_script",
    stage="artifact_registry",
)


@dataclass(frozen=True)
class ArtifactRegistrySessionStampBackfillResult:
    applied: bool
    ddl_applied: bool
    typed_static_rows_updated: int
    legacy_static_rows_updated: int
    rows_with_session_stamp_before: int
    rows_with_session_stamp_after: int


def migration_already_applied(run_sql: RunSql) -> bool:
    row = run_sql(
        """
        SELECT migration_entry_id
        FROM schema_migrations
        WHERE migration_id = %s
          AND status = 'applied'
        ORDER BY migration_entry_id DESC
        LIMIT 1
        """,
        (MIGRATION_ID,),
        fetch="one",
    )
    return bool(row)


def _artifact_registry_has_session_stamp(run_sql: RunSql) -> bool:
    row = run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = 'artifact_registry'
          AND column_name = 'session_stamp'
        """,
        (),
        fetch="one",
        dictionary=True,
        query_name="artifact_registry_session_stamp.column_present",
    ) or {}
    return bool(int(row.get("n") or 0)) if isinstance(row, dict) else bool(row)


def collect_artifact_registry_session_stamp_audit(run_sql: RunSql) -> dict[str, int]:
    has_session_stamp = _artifact_registry_has_session_stamp(run_sql)
    session_present_expr = (
        "CASE WHEN session_stamp IS NOT NULL AND TRIM(session_stamp) <> '' THEN 1 ELSE 0 END"
        if has_session_stamp
        else "0"
    )
    session_missing_expr = (
        "CASE WHEN session_stamp IS NULL OR TRIM(session_stamp) = '' THEN 1 ELSE 0 END"
        if has_session_stamp
        else "1"
    )
    row = run_sql(
        f"""
        SELECT
          COUNT(*) AS total_rows,
          SUM(CASE WHEN run_type = 'static' THEN 1 ELSE 0 END) AS static_rows,
          SUM(CASE WHEN run_type = 'dynamic' THEN 1 ELSE 0 END) AS dynamic_rows,
          SUM({session_present_expr}) AS rows_with_session_stamp,
          SUM(CASE WHEN run_type = 'static' AND ({session_present_expr}) THEN 1 ELSE 0 END) AS static_rows_with_session_stamp,
          SUM(
            CASE
              WHEN run_type = 'static'
               AND static_run_id IS NOT NULL
               AND ({session_missing_expr})
              THEN 1 ELSE 0
            END
          ) AS typed_static_rows_missing_session_stamp,
          SUM(
            CASE
              WHEN run_type = 'static'
               AND static_run_id IS NOT NULL
               AND ({session_missing_expr})
               AND EXISTS(
                 SELECT 1
                 FROM static_analysis_runs sar
                 WHERE sar.id = artifact_registry.static_run_id
                   AND sar.session_stamp IS NOT NULL
                   AND TRIM(COALESCE(sar.session_stamp, '')) <> ''
               )
              THEN 1 ELSE 0
            END
          ) AS typed_static_rows_joinable,
          SUM(
            CASE
              WHEN run_type = 'static'
               AND static_run_id IS NULL
               AND run_id REGEXP '^[0-9]+$'
               AND ({session_missing_expr})
              THEN 1 ELSE 0
            END
          ) AS legacy_static_rows_missing_session_stamp,
          SUM(
            CASE
              WHEN run_type = 'static'
               AND static_run_id IS NULL
               AND run_id REGEXP '^[0-9]+$'
               AND ({session_missing_expr})
               AND EXISTS(
                 SELECT 1
                 FROM static_analysis_runs sar
                 WHERE sar.id = CAST(artifact_registry.run_id AS UNSIGNED)
                   AND sar.session_stamp IS NOT NULL
                   AND TRIM(COALESCE(sar.session_stamp, '')) <> ''
               )
              THEN 1 ELSE 0
            END
          ) AS legacy_static_rows_joinable,
          SUM(CASE WHEN run_type = 'dynamic' AND ({session_present_expr}) THEN 1 ELSE 0 END) AS dynamic_rows_with_session_stamp
        FROM artifact_registry
        """,
        (),
        fetch="one",
        dictionary=True,
        query_name="artifact_registry_session_stamp.audit",
    ) or {}
    return {
        key: int(row.get(key) or 0)
        for key in (
            "total_rows",
            "static_rows",
            "dynamic_rows",
            "rows_with_session_stamp",
            "static_rows_with_session_stamp",
            "typed_static_rows_missing_session_stamp",
            "typed_static_rows_joinable",
            "legacy_static_rows_missing_session_stamp",
            "legacy_static_rows_joinable",
            "dynamic_rows_with_session_stamp",
        )
    }


def apply_artifact_registry_session_stamp_migration(run_sql: RunSql) -> dict[str, Any]:
    if migration_already_applied(run_sql):
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "migration_id": MIGRATION_ID,
            "schema_version_before": latest_schema_version(run_sql),
            "schema_version_after": SCHEMA_VERSION_AFTER,
            "already_applied": True,
        }

    before_schema_version = latest_schema_version(run_sql)
    for stmt in ARTIFACT_REGISTRY_SESSION_MIGRATION.statements:
        run_sql(stmt, (), query_name=f"schema_migrations.apply.{MIGRATION_ID}")
    append_schema_version(run_sql, SCHEMA_VERSION_AFTER)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "migration_id": MIGRATION_ID,
        "schema_version_before": before_schema_version,
        "schema_version_after": SCHEMA_VERSION_AFTER,
        "applied_statements": list(ARTIFACT_REGISTRY_SESSION_MIGRATION.statements),
    }
    receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / _RECEIPT_SUBDIR
    receipt_path = write_artifact_registry_session_stamp_receipt(payload, receipt_dir)
    record_schema_migration(
        run_sql,
        spec=ARTIFACT_REGISTRY_SESSION_MIGRATION,
        status="applied",
        schema_version_before=before_schema_version,
        schema_version_after=SCHEMA_VERSION_AFTER,
        notes="applied artifact_registry session_stamp additive column and indexes",
        receipt_path=receipt_path,
        payload=payload,
    )
    payload["receipt_path"] = receipt_path
    return payload


def backfill_artifact_registry_session_stamp(
    run_sql: RunSql,
    run_sql_rowcount: RunSqlRowcount,
    *,
    apply: bool,
) -> ArtifactRegistrySessionStampBackfillResult:
    before = collect_artifact_registry_session_stamp_audit(run_sql)
    ddl_applied = False
    if apply:
        migration_payload = apply_artifact_registry_session_stamp_migration(run_sql)
        ddl_applied = not bool(migration_payload.get("already_applied"))

    typed_rows = int(
        run_sql_rowcount(
            """
            UPDATE artifact_registry ar
            INNER JOIN static_analysis_runs sar
              ON sar.id = ar.static_run_id
            SET ar.session_stamp = sar.session_stamp
            WHERE ar.run_type = 'static'
              AND ar.static_run_id IS NOT NULL
              AND sar.session_stamp IS NOT NULL
              AND TRIM(COALESCE(sar.session_stamp, '')) <> ''
              AND (ar.session_stamp IS NULL OR TRIM(ar.session_stamp) = '')
            """,
            (),
            query_name="artifact_registry_session_stamp.backfill_typed_static",
        )
        if apply
        else before["typed_static_rows_joinable"]
    )
    legacy_rows = int(
        run_sql_rowcount(
            """
            UPDATE artifact_registry ar
            INNER JOIN static_analysis_runs sar
              ON sar.id = CAST(ar.run_id AS UNSIGNED)
            SET ar.session_stamp = sar.session_stamp
            WHERE ar.run_type = 'static'
              AND ar.static_run_id IS NULL
              AND ar.run_id REGEXP '^[0-9]+$'
              AND sar.session_stamp IS NOT NULL
              AND TRIM(COALESCE(sar.session_stamp, '')) <> ''
              AND (ar.session_stamp IS NULL OR TRIM(ar.session_stamp) = '')
            """,
            (),
            query_name="artifact_registry_session_stamp.backfill_legacy_static",
        )
        if apply
        else before["legacy_static_rows_joinable"]
    )
    after = collect_artifact_registry_session_stamp_audit(run_sql) if apply else {
        **before,
        "rows_with_session_stamp": before["rows_with_session_stamp"] + typed_rows + legacy_rows,
    }
    return ArtifactRegistrySessionStampBackfillResult(
        applied=bool(apply),
        ddl_applied=ddl_applied,
        typed_static_rows_updated=typed_rows,
        legacy_static_rows_updated=legacy_rows,
        rows_with_session_stamp_before=int(before["rows_with_session_stamp"]),
        rows_with_session_stamp_after=int(after["rows_with_session_stamp"]),
    )


def write_artifact_registry_session_stamp_receipt(payload: dict[str, Any], output_dir: Path) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    path = output_dir / f"artifact_registry_session_stamp_{stamp}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return str(path.resolve())


__all__ = [
    "ARTIFACT_REGISTRY_SESSION_MIGRATION",
    "ArtifactRegistrySessionStampBackfillResult",
    "MIGRATION_ID",
    "SCHEMA_VERSION_AFTER",
    "apply_artifact_registry_session_stamp_migration",
    "backfill_artifact_registry_session_stamp",
    "collect_artifact_registry_session_stamp_audit",
    "migration_already_applied",
    "write_artifact_registry_session_stamp_receipt",
]
