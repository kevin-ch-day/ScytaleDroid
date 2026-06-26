"""Schema hardening helpers for ``static_session_run_links``."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .schema_migration_registry import (
    MigrationSpec,
    append_schema_version,
    latest_rows_by_migration,
    latest_schema_version,
    record_schema_migration,
)

RunSql = Callable[..., Any]

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RECEIPT_SUBDIR = "static_session_run_links_schema"

MIGRATION_ID = "20260626_static_session_run_links_schema_v1"
SCHEMA_VERSION_AFTER = "0.3.13-static-session-run-links-schema"
TARGET_TABLE_COLLATION = "utf8mb4_unicode_ci"
TARGET_TABLE_CHARSET = "utf8mb4"
TARGET_TABLE = "static_session_run_links"
TARGET_PARENT_TABLE = "static_analysis_runs"
TARGET_PARENT_COLUMN = "id"
TARGET_FK_NAME = "fk_static_session_run_static"
TARGET_INDEX_NAME = "ix_static_session_run_origin"


TARGET_TEXT_COLUMNS: tuple[dict[str, Any], ...] = (
    {
        "column": "run_origin",
        "definition": "VARCHAR(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'created'",
        "type": "varchar(16)",
        "nullable": "NO",
        "default": "created",
    },
    {
        "column": "origin_session_stamp",
        "definition": "VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL",
        "type": "varchar(128)",
        "nullable": "YES",
        "default": None,
    },
    {
        "column": "pipeline_version",
        "definition": "VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL",
        "type": "varchar(32)",
        "nullable": "NO",
        "default": None,
    },
    {
        "column": "base_apk_sha256",
        "definition": "CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL",
        "type": "char(64)",
        "nullable": "NO",
        "default": None,
    },
    {
        "column": "artifact_set_hash",
        "definition": "CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL",
        "type": "char(64)",
        "nullable": "NO",
        "default": None,
    },
    {
        "column": "run_signature",
        "definition": "CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL",
        "type": "char(64)",
        "nullable": "NO",
        "default": None,
    },
    {
        "column": "run_signature_version",
        "definition": "VARCHAR(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL",
        "type": "varchar(16)",
        "nullable": "NO",
        "default": None,
    },
    {
        "column": "identity_error_reason",
        "definition": "VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL",
        "type": "varchar(128)",
        "nullable": "YES",
        "default": None,
    },
)


STATIC_SESSION_RUN_LINKS_SCHEMA_MIGRATION = MigrationSpec(
    migration_id=MIGRATION_ID,
    migration_name="Static session-run-links schema hardening",
    schema_version_before="0.3.12-artifact-registry-session-stamp",
    schema_version_after=SCHEMA_VERSION_AFTER,
    statements=(
        "ALTER TABLE static_session_run_links DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
        "ALTER TABLE static_session_run_links "
        "MODIFY COLUMN run_origin VARCHAR(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'created', "
        "MODIFY COLUMN origin_session_stamp VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL, "
        "MODIFY COLUMN pipeline_version VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL, "
        "MODIFY COLUMN base_apk_sha256 CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL, "
        "MODIFY COLUMN artifact_set_hash CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL, "
        "MODIFY COLUMN run_signature CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL, "
        "MODIFY COLUMN run_signature_version VARCHAR(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL, "
        "MODIFY COLUMN identity_error_reason VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL",
        "CREATE INDEX IF NOT EXISTS ix_static_session_run_origin ON static_session_run_links (origin_session_stamp)",
        "ALTER TABLE static_session_run_links "
        "ADD CONSTRAINT fk_static_session_run_static FOREIGN KEY (static_run_id) "
        "REFERENCES static_analysis_runs (id) ON DELETE CASCADE",
    ),
    description=(
        "Normalizes static_session_run_links table-default and metadata-column collations to utf8mb4_unicode_ci, "
        "adds the missing origin_session_stamp index, and restores the static_run_id FK."
    ),
    apply_mode="manual_script",
    stage="static_schema",
)


@dataclass(frozen=True)
class StaticSessionRunLinksSchemaResult:
    applied: bool
    statement_count: int
    table_default_updated: bool
    text_columns_updated: int
    index_added: bool
    foreign_key_added: bool
    receipt_path: str


def _row(run_sql: RunSql, sql: str, params: Sequence[Any] = (), *, query_name: str) -> dict[str, Any]:
    out = run_sql(sql, tuple(params), fetch="one", dictionary=True, query_name=query_name) or {}
    return dict(out) if isinstance(out, Mapping) else {}


def _rows(run_sql: RunSql, sql: str, params: Sequence[Any] = (), *, query_name: str) -> list[dict[str, Any]]:
    out = run_sql(sql, tuple(params), fetch="all", dictionary=True, query_name=query_name) or []
    return [dict(row) for row in out if isinstance(row, Mapping)]


def target_text_columns() -> tuple[dict[str, Any], ...]:
    return TARGET_TEXT_COLUMNS


def _table_collation(run_sql: RunSql) -> str:
    row = _row(
        run_sql,
        """
        SELECT table_collation
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        """,
        (TARGET_TABLE,),
        query_name="static_session_run_links_schema.table_collation",
    )
    return str(row.get("table_collation") or "").strip()


def _column_rows(run_sql: RunSql) -> dict[str, dict[str, Any]]:
    rows = _rows(
        run_sql,
        f"""
        SELECT
          column_name,
          column_type,
          is_nullable,
          column_default,
          character_set_name,
          collation_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name IN ({", ".join(["%s"] * len(TARGET_TEXT_COLUMNS))})
        ORDER BY ordinal_position
        """,
        (TARGET_TABLE, *(spec["column"] for spec in TARGET_TEXT_COLUMNS)),
        query_name="static_session_run_links_schema.columns",
    )
    return {str(row.get("column_name") or "").strip(): row for row in rows}


def _index_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    return _rows(
        run_sql,
        """
        SELECT index_name, column_name, seq_in_index
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = %s
        ORDER BY index_name, seq_in_index
        """,
        (TARGET_TABLE,),
        query_name="static_session_run_links_schema.indexes",
    )


def _fk_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    return _rows(
        run_sql,
        """
        SELECT
          kcu.constraint_name,
          kcu.column_name,
          kcu.referenced_table_name,
          kcu.referenced_column_name,
          rc.delete_rule
        FROM information_schema.key_column_usage kcu
        JOIN information_schema.referential_constraints rc
          ON rc.constraint_schema = kcu.table_schema
         AND rc.constraint_name = kcu.constraint_name
        WHERE kcu.table_schema = DATABASE()
          AND kcu.table_name = %s
          AND kcu.referenced_table_name IS NOT NULL
        ORDER BY kcu.constraint_name, kcu.ordinal_position
        """,
        (TARGET_TABLE,),
        query_name="static_session_run_links_schema.foreign_keys",
    )


def _unlinked_static_run_rows(run_sql: RunSql) -> int:
    row = _row(
        run_sql,
        f"""
        SELECT COUNT(*) AS n
        FROM {TARGET_TABLE} l
        LEFT JOIN {TARGET_PARENT_TABLE} r
          ON r.{TARGET_PARENT_COLUMN} = l.static_run_id
        WHERE l.static_run_id IS NULL
           OR r.{TARGET_PARENT_COLUMN} IS NULL
        """,
        (),
        query_name="static_session_run_links_schema.unlinked_static_runs",
    )
    return int(row.get("n") or 0)


def _normalize_default(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return ""
    if text.upper() == "NULL":
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    return text


def _migration_already_recorded(run_sql: RunSql) -> bool:
    row = latest_rows_by_migration(run_sql).get(MIGRATION_ID) or {}
    return str(row.get("status") or "").strip().lower() == "applied"


def _record_static_session_run_links_schema_migration(
    run_sql: RunSql,
    *,
    before_schema_version: str | None,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    statements: Sequence[str],
) -> str:
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "migration_id": MIGRATION_ID,
        "schema_version_before": before_schema_version,
        "schema_version_after": SCHEMA_VERSION_AFTER,
        "before": before,
        "after": after,
        "applied_statements": list(statements),
    }
    receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / _RECEIPT_SUBDIR
    receipt_path = write_static_session_run_links_schema_receipt(payload, receipt_dir)
    record_schema_migration(
        run_sql,
        spec=STATIC_SESSION_RUN_LINKS_SCHEMA_MIGRATION,
        status="applied",
        schema_version_before=before_schema_version,
        schema_version_after=SCHEMA_VERSION_AFTER,
        notes="normalized static_session_run_links metadata collations and restored integrity helpers",
        receipt_path=receipt_path,
        payload={
            "statement_count": len(statements),
            "table_default_updated": bool(before.get("table_default_needs_change")),
            "text_columns_updated": int(before.get("text_columns_needing_normalization") or 0),
            "index_added": bool(before.get("missing_origin_session_stamp_index")),
            "foreign_key_added": bool(before.get("missing_static_run_fk")),
        },
    )
    append_schema_version(run_sql, SCHEMA_VERSION_AFTER)
    return receipt_path


def collect_static_session_run_links_schema_audit(run_sql: RunSql) -> dict[str, Any]:
    table_collation = _table_collation(run_sql)
    column_rows = _column_rows(run_sql)
    index_rows = _index_rows(run_sql)
    fk_rows = _fk_rows(run_sql)
    unlinked_rows = _unlinked_static_run_rows(run_sql)

    columns: list[dict[str, Any]] = []
    missing_columns: list[str] = []
    text_columns_needing_normalization = 0
    for spec in TARGET_TEXT_COLUMNS:
        column_name = str(spec["column"])
        current = column_rows.get(column_name)
        if not current:
            missing_columns.append(column_name)
            columns.append(
                {
                    "column": column_name,
                    "present": False,
                    "needs_change": True,
                }
            )
            text_columns_needing_normalization += 1
            continue
        current_type = str(current.get("column_type") or "").lower()
        current_charset = str(current.get("character_set_name") or "").strip()
        current_collation = str(current.get("collation_name") or "").strip()
        current_nullable = str(current.get("is_nullable") or "").strip().upper()
        current_default = _normalize_default(current.get("column_default"))
        needs_change = any(
            (
                current_type != str(spec["type"]),
                current_charset != TARGET_TABLE_CHARSET,
                current_collation != TARGET_TABLE_COLLATION,
                current_nullable != str(spec["nullable"]),
                current_default != spec["default"],
            )
        )
        if needs_change:
            text_columns_needing_normalization += 1
        columns.append(
            {
                "column": column_name,
                "present": True,
                "current_type": current_type,
                "current_charset": current_charset,
                "current_collation": current_collation,
                "current_nullable": current_nullable,
                "current_default": current_default,
                "target_type": spec["type"],
                "target_charset": TARGET_TABLE_CHARSET,
                "target_collation": TARGET_TABLE_COLLATION,
                "target_nullable": spec["nullable"],
                "target_default": spec["default"],
                "needs_change": needs_change,
            }
        )

    index_columns = {
        ",".join(
            str(row.get("column_name") or "").strip()
            for row in index_rows
            if str(row.get("index_name") or "").strip() == index_name
        )
        for index_name in {
            str(row.get("index_name") or "").strip()
            for row in index_rows
            if str(row.get("index_name") or "").strip() and str(row.get("index_name") or "").strip() != "PRIMARY"
        }
    }
    has_origin_index = "origin_session_stamp" in index_columns

    has_static_run_fk = False
    fk_delete_rule = None
    for row in fk_rows:
        if (
            str(row.get("column_name") or "").strip() == "static_run_id"
            and str(row.get("referenced_table_name") or "").strip() == TARGET_PARENT_TABLE
            and str(row.get("referenced_column_name") or "").strip() == TARGET_PARENT_COLUMN
        ):
            has_static_run_fk = True
            fk_delete_rule = str(row.get("delete_rule") or "").strip().upper() or None
            break

    fk_rule_matches = has_static_run_fk and fk_delete_rule == "CASCADE"
    missing_fk = not fk_rule_matches
    table_default_needs_change = table_collation != TARGET_TABLE_COLLATION
    required_statement_count = int(table_default_needs_change) + int(text_columns_needing_normalization > 0) + int(not has_origin_index) + int(missing_fk)
    apply_safe = not missing_columns and unlinked_rows == 0

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "table_name": TARGET_TABLE,
        "table_default_collation": table_collation,
        "target_table_collation": TARGET_TABLE_COLLATION,
        "table_default_needs_change": table_default_needs_change,
        "columns": columns,
        "missing_columns": missing_columns,
        "text_columns_needing_normalization": text_columns_needing_normalization,
        "has_origin_session_stamp_index": has_origin_index,
        "missing_origin_session_stamp_index": not has_origin_index,
        "has_static_run_fk": has_static_run_fk,
        "fk_delete_rule": fk_delete_rule,
        "missing_static_run_fk": missing_fk,
        "unlinked_static_run_rows": unlinked_rows,
        "required_statement_count": required_statement_count,
        "apply_safe": apply_safe,
    }


def build_required_static_session_run_links_schema_statements(audit: Mapping[str, Any]) -> list[str]:
    statements: list[str] = []
    if bool(audit.get("table_default_needs_change")):
        statements.append(
            f"ALTER TABLE {TARGET_TABLE} DEFAULT CHARACTER SET {TARGET_TABLE_CHARSET} COLLATE {TARGET_TABLE_COLLATION}"
        )
    columns = audit.get("columns") or []
    modify_specs: list[str] = []
    for row in columns:
        if not isinstance(row, Mapping) or not bool(row.get("needs_change")) or not bool(row.get("present")):
            continue
        column_name = str(row.get("column") or "")
        spec = next(spec for spec in TARGET_TEXT_COLUMNS if spec["column"] == column_name)
        modify_specs.append(f"MODIFY COLUMN {column_name} {spec['definition']}")
    if modify_specs:
        statements.append(f"ALTER TABLE {TARGET_TABLE} " + ", ".join(modify_specs))
    if bool(audit.get("missing_origin_session_stamp_index")):
        statements.append(
            f"CREATE INDEX IF NOT EXISTS {TARGET_INDEX_NAME} ON {TARGET_TABLE} (origin_session_stamp)"
        )
    if bool(audit.get("missing_static_run_fk")):
        statements.append(
            f"ALTER TABLE {TARGET_TABLE} "
            f"ADD CONSTRAINT {TARGET_FK_NAME} FOREIGN KEY (static_run_id) "
            f"REFERENCES {TARGET_PARENT_TABLE} ({TARGET_PARENT_COLUMN}) ON DELETE CASCADE"
        )
    return statements


def write_static_session_run_links_schema_receipt(payload: Mapping[str, Any], output_dir: Path) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / f"static_session_run_links_schema_{stamp}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return str(path.resolve())


def apply_static_session_run_links_schema_normalization(run_sql: RunSql) -> StaticSessionRunLinksSchemaResult:
    before = collect_static_session_run_links_schema_audit(run_sql)
    statements = build_required_static_session_run_links_schema_statements(before)
    before_schema_version = latest_schema_version(run_sql)
    if not statements:
        if bool(before.get("apply_safe")) and (before_schema_version != SCHEMA_VERSION_AFTER or not _migration_already_recorded(run_sql)):
            receipt_path = _record_static_session_run_links_schema_migration(
                run_sql,
                before_schema_version=before_schema_version,
                before=before,
                after=before,
                statements=(),
            )
            return StaticSessionRunLinksSchemaResult(
                applied=True,
                statement_count=0,
                table_default_updated=False,
                text_columns_updated=0,
                index_added=False,
                foreign_key_added=False,
                receipt_path=receipt_path,
            )
        return StaticSessionRunLinksSchemaResult(
            applied=False,
            statement_count=0,
            table_default_updated=False,
            text_columns_updated=0,
            index_added=False,
            foreign_key_added=False,
            receipt_path="",
        )
    if not bool(before.get("apply_safe")):
        raise RuntimeError(
            "static_session_run_links schema normalization preflight failed: "
            f"missing_columns={before.get('missing_columns') or []} "
            f"unlinked_static_run_rows={int(before.get('unlinked_static_run_rows') or 0)}"
        )

    for statement in statements:
        run_sql(statement, (), query_name=f"schema_migrations.apply.{MIGRATION_ID}")
    after = collect_static_session_run_links_schema_audit(run_sql)
    if build_required_static_session_run_links_schema_statements(after):
        raise RuntimeError("static_session_run_links schema normalization did not converge cleanly")

    receipt_path = _record_static_session_run_links_schema_migration(
        run_sql,
        before_schema_version=before_schema_version,
        before=before,
        after=after,
        statements=statements,
    )
    return StaticSessionRunLinksSchemaResult(
        applied=True,
        statement_count=len(statements),
        table_default_updated=bool(before.get("table_default_needs_change")),
        text_columns_updated=int(before.get("text_columns_needing_normalization") or 0),
        index_added=bool(before.get("missing_origin_session_stamp_index")),
        foreign_key_added=bool(before.get("missing_static_run_fk")),
        receipt_path=receipt_path,
    )


__all__ = [
    "MIGRATION_ID",
    "SCHEMA_VERSION_AFTER",
    "STATIC_SESSION_RUN_LINKS_SCHEMA_MIGRATION",
    "StaticSessionRunLinksSchemaResult",
    "apply_static_session_run_links_schema_normalization",
    "build_required_static_session_run_links_schema_statements",
    "collect_static_session_run_links_schema_audit",
    "target_text_columns",
    "write_static_session_run_links_schema_receipt",
]
