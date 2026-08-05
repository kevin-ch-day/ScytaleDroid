"""Additive persistence migration for Quiescent Foreground baseline evidence."""

from __future__ import annotations

from collections.abc import Callable

from .schema_migration_registry import (
    MigrationSpec,
    append_schema_version,
    latest_schema_version,
    record_schema_migration,
)

RunSql = Callable[..., object]

MIGRATION_ID = "20260719_dynamic_session_qfg_metadata_v1"
SCHEMA_VERSION_AFTER = "0.3.15-dynamic-session-qfg-metadata"

DYNAMIC_SESSION_QFG_MIGRATION = MigrationSpec(
    migration_id=MIGRATION_ID,
    migration_name="Persist quiescent foreground baseline metadata on dynamic sessions",
    schema_version_before="0.3.14-static-finding-evidence-payload-schema",
    schema_version_after=SCHEMA_VERSION_AFTER,
    statements=(
        "ALTER TABLE dynamic_sessions ADD COLUMN IF NOT EXISTS baseline_not_idle TINYINT(1) DEFAULT NULL",
        "ALTER TABLE dynamic_sessions ADD COLUMN IF NOT EXISTS baseline_not_idle_reasons_json JSON DEFAULT NULL",
    ),
    description=(
        "Records the existing baseline activity classification and reason codes from evidence packs. "
        "This is descriptive metadata only; it does not alter validity or countability."
    ),
    apply_mode="manual_script",
    stage="dynamic_read_model",
)


def migration_already_applied(run_sql: RunSql) -> bool:
    row = run_sql(
        """
        SELECT migration_entry_id
        FROM schema_migrations
        WHERE migration_id = %s AND status = 'applied'
        ORDER BY migration_entry_id DESC
        LIMIT 1
        """,
        (MIGRATION_ID,),
        fetch="one",
    )
    return bool(row)


def apply_dynamic_session_qfg_schema(run_sql: RunSql) -> bool:
    """Apply the idempotent column migration and record it once."""

    if migration_already_applied(run_sql):
        return False
    before = latest_schema_version(run_sql) or DYNAMIC_SESSION_QFG_MIGRATION.schema_version_before
    for statement in DYNAMIC_SESSION_QFG_MIGRATION.statements:
        run_sql(statement, (), query_name="dynamic_session_qfg_schema.apply")
    record_schema_migration(
        run_sql,
        spec=DYNAMIC_SESSION_QFG_MIGRATION,
        status="applied",
        schema_version_before=before,
        schema_version_after=SCHEMA_VERSION_AFTER,
        notes="additive QFG metadata columns; existing evidence requires explicit reindex",
    )
    append_schema_version(run_sql, SCHEMA_VERSION_AFTER)
    return True


__all__ = [
    "DYNAMIC_SESSION_QFG_MIGRATION",
    "MIGRATION_ID",
    "SCHEMA_VERSION_AFTER",
    "apply_dynamic_session_qfg_schema",
    "migration_already_applied",
]
