"""Schema hardening helpers for ``static_finding_evidence_payloads``."""

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
_RECEIPT_SUBDIR = "static_finding_evidence_payload_schema"

MIGRATION_ID = "20260626_static_finding_evidence_payload_schema_v1"
SCHEMA_VERSION_AFTER = "0.3.14-static-finding-evidence-payload-schema"
TARGET_TABLE = "static_finding_evidence_payloads"
TARGET_TABLE_CHARSET = "utf8mb4"
TARGET_TABLE_COLLATION = "utf8mb4_unicode_ci"


STATIC_FINDING_EVIDENCE_PAYLOAD_SCHEMA_MIGRATION = MigrationSpec(
    migration_id=MIGRATION_ID,
    migration_name="Static finding evidence payload schema hardening",
    schema_version_before="0.3.13-static-session-run-links-schema",
    schema_version_after=SCHEMA_VERSION_AFTER,
    statements=(
        "ALTER TABLE static_finding_evidence_payloads DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
        "ALTER TABLE static_finding_evidence_payloads "
        "MODIFY COLUMN evidence_json LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL, "
        "MODIFY COLUMN evidence_chars INT UNSIGNED NOT NULL, "
        "MODIFY COLUMN first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",
    ),
    description=(
        "Normalizes the canonical static finding evidence payload store to utf8mb4_unicode_ci and "
        "aligns evidence_chars/first_seen_at with the canonical DDL."
    ),
    apply_mode="manual_script",
    stage="static_schema",
)


@dataclass(frozen=True)
class StaticFindingEvidencePayloadSchemaResult:
    applied: bool
    statement_count: int
    table_default_updated: bool
    evidence_json_updated: bool
    evidence_chars_updated: bool
    first_seen_at_updated: bool
    receipt_path: str


def _row(run_sql: RunSql, sql: str, params: Sequence[Any] = (), *, query_name: str) -> dict[str, Any]:
    out = run_sql(sql, tuple(params), fetch="one", dictionary=True, query_name=query_name) or {}
    return dict(out) if isinstance(out, Mapping) else {}


def _rows(run_sql: RunSql, sql: str, params: Sequence[Any] = (), *, query_name: str) -> list[dict[str, Any]]:
    out = run_sql(sql, tuple(params), fetch="all", dictionary=True, query_name=query_name) or []
    return [dict(row) for row in out if isinstance(row, Mapping)]


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
        query_name="static_finding_evidence_payload_schema.table_collation",
    )
    return str(row.get("table_collation") or "").strip()


def _column_rows(run_sql: RunSql) -> dict[str, dict[str, Any]]:
    rows = _rows(
        run_sql,
        """
        SELECT
          column_name,
          data_type,
          column_type,
          character_set_name,
          collation_name,
          is_nullable,
          column_default
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name IN ('evidence_json', 'evidence_chars', 'first_seen_at')
        ORDER BY ordinal_position
        """,
        (TARGET_TABLE,),
        query_name="static_finding_evidence_payload_schema.columns",
    )
    return {str(row.get("column_name") or "").strip(): row for row in rows}


def collect_static_finding_evidence_payload_schema_audit(run_sql: RunSql) -> dict[str, Any]:
    table_collation = _table_collation(run_sql)
    columns = _column_rows(run_sql)
    stats = _row(
        run_sql,
        f"""
        SELECT
          COUNT(*) AS rows_n,
          SUM(CASE WHEN evidence_chars < 0 THEN 1 ELSE 0 END) AS negative_chars,
          SUM(CASE WHEN first_seen_at IS NULL THEN 1 ELSE 0 END) AS null_first_seen,
          MAX(CHAR_LENGTH(evidence_json)) AS max_chars,
          SUM(CASE WHEN evidence_json REGEXP '[^ -~]' THEN 1 ELSE 0 END) AS non_ascii_rows
        FROM {TARGET_TABLE}
        """,
        (),
        query_name="static_finding_evidence_payload_schema.stats",
    )

    evidence_json = columns.get("evidence_json") or {}
    evidence_chars = columns.get("evidence_chars") or {}
    first_seen_at = columns.get("first_seen_at") or {}

    evidence_json_needs_change = any(
        (
            str(evidence_json.get("data_type") or "").lower() != "longtext",
            str(evidence_json.get("character_set_name") or "") != TARGET_TABLE_CHARSET,
            str(evidence_json.get("collation_name") or "") != TARGET_TABLE_COLLATION,
            str(evidence_json.get("is_nullable") or "").upper() != "NO",
        )
    )
    evidence_chars_needs_change = any(
        (
            str(evidence_chars.get("column_type") or "").lower() != "int(10) unsigned",
            str(evidence_chars.get("is_nullable") or "").upper() != "NO",
            int(stats.get("negative_chars") or 0) != 0,
        )
    )
    first_seen_needs_change = any(
        (
            str(first_seen_at.get("data_type") or "").lower() != "timestamp",
            str(first_seen_at.get("is_nullable") or "").upper() != "NO",
            _normalize_default(first_seen_at.get("column_default")) not in {"current_timestamp()", "current_timestamp"},
            int(stats.get("null_first_seen") or 0) != 0,
        )
    )
    table_default_needs_change = table_collation != TARGET_TABLE_COLLATION
    required_statement_count = int(table_default_needs_change) + int(
        evidence_json_needs_change or evidence_chars_needs_change or first_seen_needs_change
    )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "table_name": TARGET_TABLE,
        "table_default_collation": table_collation,
        "target_table_collation": TARGET_TABLE_COLLATION,
        "table_default_needs_change": table_default_needs_change,
        "rows_n": int(stats.get("rows_n") or 0),
        "negative_chars": int(stats.get("negative_chars") or 0),
        "null_first_seen": int(stats.get("null_first_seen") or 0),
        "max_chars": int(stats.get("max_chars") or 0),
        "non_ascii_rows": int(stats.get("non_ascii_rows") or 0),
        "evidence_json": {
            "data_type": evidence_json.get("data_type"),
            "column_type": evidence_json.get("column_type"),
            "charset": evidence_json.get("character_set_name"),
            "collation": evidence_json.get("collation_name"),
            "nullable": evidence_json.get("is_nullable"),
            "needs_change": evidence_json_needs_change,
        },
        "evidence_chars": {
            "column_type": evidence_chars.get("column_type"),
            "nullable": evidence_chars.get("is_nullable"),
            "needs_change": evidence_chars_needs_change,
        },
        "first_seen_at": {
            "data_type": first_seen_at.get("data_type"),
            "column_type": first_seen_at.get("column_type"),
            "nullable": first_seen_at.get("is_nullable"),
            "default": _normalize_default(first_seen_at.get("column_default")),
            "needs_change": first_seen_needs_change,
        },
        "required_statement_count": required_statement_count,
        "apply_safe": int(stats.get("negative_chars") or 0) == 0 and int(stats.get("null_first_seen") or 0) == 0,
    }


def build_required_static_finding_evidence_payload_schema_statements(audit: Mapping[str, Any]) -> list[str]:
    statements: list[str] = []
    if bool(audit.get("table_default_needs_change")):
        statements.append(
            f"ALTER TABLE {TARGET_TABLE} DEFAULT CHARACTER SET {TARGET_TABLE_CHARSET} COLLATE {TARGET_TABLE_COLLATION}"
        )
    if any(
        (
            bool((audit.get("evidence_json") or {}).get("needs_change")),
            bool((audit.get("evidence_chars") or {}).get("needs_change")),
            bool((audit.get("first_seen_at") or {}).get("needs_change")),
        )
    ):
        statements.append(
            f"ALTER TABLE {TARGET_TABLE} "
            "MODIFY COLUMN evidence_json LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL, "
            "MODIFY COLUMN evidence_chars INT UNSIGNED NOT NULL, "
            "MODIFY COLUMN first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        )
    return statements


def write_static_finding_evidence_payload_schema_receipt(payload: Mapping[str, Any], output_dir: Path) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / f"static_finding_evidence_payload_schema_{stamp}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return str(path.resolve())


def _record_static_finding_evidence_payload_schema_migration(
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
    receipt_path = write_static_finding_evidence_payload_schema_receipt(payload, receipt_dir)
    record_schema_migration(
        run_sql,
        spec=STATIC_FINDING_EVIDENCE_PAYLOAD_SCHEMA_MIGRATION,
        status="applied",
        schema_version_before=before_schema_version,
        schema_version_after=SCHEMA_VERSION_AFTER,
        notes="normalized static_finding_evidence_payloads canonical payload store",
        receipt_path=receipt_path,
        payload={
            "statement_count": len(statements),
            "table_default_updated": bool(before.get("table_default_needs_change")),
            "evidence_json_updated": bool((before.get("evidence_json") or {}).get("needs_change")),
            "evidence_chars_updated": bool((before.get("evidence_chars") or {}).get("needs_change")),
            "first_seen_at_updated": bool((before.get("first_seen_at") or {}).get("needs_change")),
        },
    )
    append_schema_version(run_sql, SCHEMA_VERSION_AFTER)
    return receipt_path


def apply_static_finding_evidence_payload_schema_normalization(run_sql: RunSql) -> StaticFindingEvidencePayloadSchemaResult:
    before = collect_static_finding_evidence_payload_schema_audit(run_sql)
    statements = build_required_static_finding_evidence_payload_schema_statements(before)
    before_schema_version = latest_schema_version(run_sql)
    if not statements:
        if bool(before.get("apply_safe")) and (before_schema_version != SCHEMA_VERSION_AFTER or not _migration_already_recorded(run_sql)):
            receipt_path = _record_static_finding_evidence_payload_schema_migration(
                run_sql,
                before_schema_version=before_schema_version,
                before=before,
                after=before,
                statements=(),
            )
            return StaticFindingEvidencePayloadSchemaResult(
                applied=True,
                statement_count=0,
                table_default_updated=False,
                evidence_json_updated=False,
                evidence_chars_updated=False,
                first_seen_at_updated=False,
                receipt_path=receipt_path,
            )
        return StaticFindingEvidencePayloadSchemaResult(
            applied=False,
            statement_count=0,
            table_default_updated=False,
            evidence_json_updated=False,
            evidence_chars_updated=False,
            first_seen_at_updated=False,
            receipt_path="",
        )
    if not bool(before.get("apply_safe")):
        raise RuntimeError(
            "static_finding_evidence_payloads schema normalization preflight failed: "
            f"negative_chars={int(before.get('negative_chars') or 0)} "
            f"null_first_seen={int(before.get('null_first_seen') or 0)}"
        )
    for statement in statements:
        run_sql(statement, (), query_name=f"schema_migrations.apply.{MIGRATION_ID}")
    after = collect_static_finding_evidence_payload_schema_audit(run_sql)
    if build_required_static_finding_evidence_payload_schema_statements(after):
        raise RuntimeError("static_finding_evidence_payloads schema normalization did not converge cleanly")
    receipt_path = _record_static_finding_evidence_payload_schema_migration(
        run_sql,
        before_schema_version=before_schema_version,
        before=before,
        after=after,
        statements=statements,
    )
    return StaticFindingEvidencePayloadSchemaResult(
        applied=True,
        statement_count=len(statements),
        table_default_updated=bool(before.get("table_default_needs_change")),
        evidence_json_updated=bool((before.get("evidence_json") or {}).get("needs_change")),
        evidence_chars_updated=bool((before.get("evidence_chars") or {}).get("needs_change")),
        first_seen_at_updated=bool((before.get("first_seen_at") or {}).get("needs_change")),
        receipt_path=receipt_path,
    )


__all__ = [
    "MIGRATION_ID",
    "SCHEMA_VERSION_AFTER",
    "STATIC_FINDING_EVIDENCE_PAYLOAD_SCHEMA_MIGRATION",
    "StaticFindingEvidencePayloadSchemaResult",
    "apply_static_finding_evidence_payload_schema_normalization",
    "build_required_static_finding_evidence_payload_schema_statements",
    "collect_static_finding_evidence_payload_schema_audit",
    "write_static_finding_evidence_payload_schema_receipt",
]
