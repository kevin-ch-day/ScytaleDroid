"""Phase A additive typed replacement column apply/backfill helpers."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .schema_migration_registry import (
    append_schema_version,
    latest_rows_by_migration,
    latest_schema_version,
    record_schema_migration,
    registered_migrations,
)
from .type_normalization_preflight import collect_type_normalization_preflight

RunSql = Callable[..., Any]
RunSqlRowcount = Callable[..., int]


@dataclass(frozen=True)
class PhaseAApplyResult:
    ddl_applied: bool
    artifact_registry_dynamic_run_uuid_backfilled: int
    dynamic_sessions_static_run_id_u_backfilled: int
    static_analysis_runs_run_started_at_utc_backfilled: int
    latest_schema_version_after: str | None


def _typed_column_migration():
    return registered_migrations()[1]


def _typed_backfill_migration():
    return registered_migrations()[2]


def migration_already_applied(run_sql: RunSql, migration_id: str) -> bool:
    latest = latest_rows_by_migration(run_sql).get(migration_id) or {}
    return str(latest.get("status") or "").strip().lower() == "applied"


def apply_typed_replacement_columns(run_sql: RunSql) -> bool:
    spec = _typed_column_migration()
    if migration_already_applied(run_sql, spec.migration_id):
        return False
    before = latest_schema_version(run_sql) or spec.schema_version_before
    receipt_note = "manual phase-a typed replacement DDL"
    try:
        for stmt in spec.statements:
            run_sql(stmt, (), query_name=f"schema_migrations.apply.{spec.migration_id}")
        record_schema_migration(
            run_sql,
            spec=spec,
            status="applied",
            schema_version_before=before,
            schema_version_after=spec.schema_version_after,
            notes=receipt_note,
        )
        append_schema_version(run_sql, spec.schema_version_after)
        return True
    except Exception as exc:
        try:
            record_schema_migration(
                run_sql,
                spec=spec,
                status="failed",
                schema_version_before=before,
                schema_version_after=spec.schema_version_after,
                notes=f"{receipt_note}: {type(exc).__name__}: {exc}",
            )
        except Exception:
            pass
        raise


def backfill_typed_replacement_columns(run_sql: RunSql, run_sql_rowcount: RunSqlRowcount) -> PhaseAApplyResult:
    preflight = collect_type_normalization_preflight(run_sql)
    if not bool((preflight.get("summary") or {}).get("preflight_clean")):
        raise ValueError("type-normalization preflight is not clean; refusing additive typed backfill")

    ddl_applied = apply_typed_replacement_columns(run_sql)
    before = latest_schema_version(run_sql) or _typed_backfill_migration().schema_version_before

    artifact_rows = int(
        run_sql_rowcount(
            """
            UPDATE artifact_registry
            SET dynamic_run_uuid = LOWER(TRIM(dynamic_run_id))
            WHERE run_type = 'dynamic'
              AND dynamic_run_id IS NOT NULL
              AND TRIM(dynamic_run_id) <> ''
              AND dynamic_run_uuid IS NULL
              AND CHAR_LENGTH(dynamic_run_id) = 36
              AND dynamic_run_id REGEXP '^[0-9a-fA-F-]{36}$'
            """,
            (),
            query_name="phase_a_typed_replacements.backfill_artifact_registry",
        )
    )
    dynamic_rows = int(
        run_sql_rowcount(
            """
            UPDATE dynamic_sessions ds
            LEFT JOIN static_analysis_runs sar
              ON sar.id = CAST(ds.static_run_id AS UNSIGNED)
            SET ds.static_run_id_u = CAST(ds.static_run_id AS UNSIGNED)
            WHERE ds.static_run_id IS NOT NULL
              AND ds.static_run_id_u IS NULL
              AND sar.id IS NOT NULL
            """,
            (),
            query_name="phase_a_typed_replacements.backfill_dynamic_sessions",
        )
    )
    static_rows = int(
        run_sql_rowcount(
            """
            UPDATE static_analysis_runs
            SET run_started_at_utc = COALESCE(
                STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f'),
                STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')
            )
            WHERE run_started_utc IS NOT NULL
              AND TRIM(run_started_utc) <> ''
              AND run_started_at_utc IS NULL
              AND (
                STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f') IS NOT NULL
                OR STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s') IS NOT NULL
              )
            """,
            (),
            query_name="phase_a_typed_replacements.backfill_static_runs",
        )
    )

    spec = _typed_backfill_migration()
    payload = {
        "ddl_applied": ddl_applied,
        "artifact_registry_dynamic_run_uuid_backfilled": artifact_rows,
        "dynamic_sessions_static_run_id_u_backfilled": dynamic_rows,
        "static_analysis_runs_run_started_at_utc_backfilled": static_rows,
    }
    if not migration_already_applied(run_sql, spec.migration_id):
        record_schema_migration(
            run_sql,
            spec=spec,
            status="applied",
            schema_version_before=before,
            schema_version_after=spec.schema_version_after,
            notes="manual phase-a typed replacement backfill",
            payload=payload,
        )
        append_schema_version(run_sql, spec.schema_version_after)
    return PhaseAApplyResult(
        ddl_applied=ddl_applied,
        artifact_registry_dynamic_run_uuid_backfilled=artifact_rows,
        dynamic_sessions_static_run_id_u_backfilled=dynamic_rows,
        static_analysis_runs_run_started_at_utc_backfilled=static_rows,
        latest_schema_version_after=latest_schema_version(run_sql),
    )


def write_phase_a_backfill_receipt(output_dir: Path, *, stem: str, payload: Mapping[str, Any]) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{stem}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return str(path.resolve())


__all__ = [
    "PhaseAApplyResult",
    "apply_typed_replacement_columns",
    "backfill_typed_replacement_columns",
    "migration_already_applied",
    "write_phase_a_backfill_receipt",
]
