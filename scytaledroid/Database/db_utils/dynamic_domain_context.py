"""Additive migration and seed helpers for dynamic domain context tables."""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_queries.canonical.schema import CREATE_DYNAMIC_DOMAIN_REFERENCE
from scytaledroid.Database.db_queries.dynamic.schema import (
    _DDL_STATEMENTS as DYNAMIC_DDL_STATEMENTS,
)
from scytaledroid.DynamicAnalysis.domain_context import default_domain_reference_seed_rows

from .schema_migration_registry import (
    MigrationSpec,
    append_schema_version,
    latest_schema_version,
    record_schema_migration,
)

RunSql = Callable[..., Any]
RunSqlMany = Callable[..., Any]

_REPO_ROOT = Path(__file__).resolve().parents[3]
RECEIPT_SUBDIR = "dynamic_domain_context"
MIGRATION_ID = "20260615_dynamic_domain_context_tables_v1"
SCHEMA_VERSION_AFTER = "0.3.8-dynamic-domain-context"
COLLATION_HOTFIX_MIGRATION_ID = "20260615_dynamic_domain_context_collation_hotfix_v1"
COLLATION_HOTFIX_SCHEMA_VERSION_AFTER = "0.3.9-dynamic-domain-context-collation-hotfix"

_CREATE_DYNAMIC_DOMAIN_OBSERVATIONS = next(
    stmt for stmt in DYNAMIC_DDL_STATEMENTS if "CREATE TABLE IF NOT EXISTS dynamic_domain_observations" in stmt
)

DYNAMIC_DOMAIN_CONTEXT_MIGRATION = MigrationSpec(
    migration_id=MIGRATION_ID,
    migration_name="Dynamic domain context reference and observation tables",
    schema_version_before="0.3.7-research-cohorts",
    schema_version_after=SCHEMA_VERSION_AFTER,
    statements=(
        CREATE_DYNAMIC_DOMAIN_REFERENCE.strip(),
        _CREATE_DYNAMIC_DOMAIN_OBSERVATIONS.strip(),
    ),
    description="Adds DB-backed background domain reference intel and rebuildable per-run dynamic domain context observations.",
    apply_mode="manual_script",
    stage="dynamic_context",
)

DYNAMIC_DOMAIN_CONTEXT_COLLATION_HOTFIX = MigrationSpec(
    migration_id=COLLATION_HOTFIX_MIGRATION_ID,
    migration_name="Dynamic domain context dynamic_run_id collation hotfix",
    schema_version_before=SCHEMA_VERSION_AFTER,
    schema_version_after=COLLATION_HOTFIX_SCHEMA_VERSION_AFTER,
    statements=(
        "ALTER TABLE dynamic_domain_observations MODIFY dynamic_run_id CHAR(36) COLLATE utf8mb4_general_ci NOT NULL",
    ),
    description="Align dynamic_domain_observations.dynamic_run_id collation with dynamic_sessions.dynamic_run_id for natural joins.",
    apply_mode="manual_script",
    stage="dynamic_context",
)


@dataclass(frozen=True)
class DomainReferenceRow:
    package_name_scope: str
    domain_pattern: str
    match_type: str
    owner_class: str
    role_class: str
    confidence: str
    classification_basis: str
    source_label: str
    source_url: str | None
    notes: str | None


def migration_already_applied(run_sql: RunSql) -> bool:
    return _migration_already_applied(run_sql, MIGRATION_ID)


def _migration_already_applied(run_sql: RunSql, migration_id: str) -> bool:
    row = run_sql(
        """
        SELECT migration_entry_id
        FROM schema_migrations
        WHERE migration_id = %s
          AND status = 'applied'
        ORDER BY migration_entry_id DESC
        LIMIT 1
        """,
        (migration_id,),
        fetch="one",
    )
    return bool(row)


def _reference_count(run_sql: RunSql) -> int:
    row = run_sql(
        "SELECT COUNT(*) AS n FROM dynamic_domain_reference",
        (),
        fetch="one",
        dictionary=True,
        query_name="dynamic_domain_context.reference_count",
    ) or {}
    if isinstance(row, Mapping):
        return int(row.get("n") or 0)
    if isinstance(row, (list, tuple)) and row:
        return int(row[0] or 0)
    return 0


def load_domain_reference_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    rows = run_sql(
        """
        SELECT
          package_name_scope,
          domain_pattern,
          match_type,
          owner_class,
          role_class,
          confidence,
          classification_basis,
          source_label,
          source_url,
          notes
        FROM dynamic_domain_reference
        WHERE is_active = 1
        ORDER BY package_name_scope, match_type, domain_pattern
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic_domain_context.load_references",
    ) or []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def upsert_domain_reference_seed_rows(run_sql: RunSql, rows: list[Mapping[str, Any]]) -> int:
    sql = """
        INSERT INTO dynamic_domain_reference (
          package_name_scope,
          domain_pattern,
          match_type,
          owner_class,
          role_class,
          confidence,
          classification_basis,
          source_label,
          source_url,
          notes,
          is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1)
        ON DUPLICATE KEY UPDATE
          owner_class = VALUES(owner_class),
          role_class = VALUES(role_class),
          confidence = VALUES(confidence),
          classification_basis = VALUES(classification_basis),
          source_label = VALUES(source_label),
          source_url = VALUES(source_url),
          notes = VALUES(notes),
          is_active = VALUES(is_active)
    """
    writes = 0
    for row in rows:
        run_sql(
            sql,
            (
                str(row.get("package_name_scope") or ""),
                str(row.get("domain_pattern") or ""),
                str(row.get("match_type") or ""),
                str(row.get("owner_class") or ""),
                str(row.get("role_class") or ""),
                str(row.get("confidence") or ""),
                str(row.get("classification_basis") or ""),
                str(row.get("source_label") or "repo_seed"),
                row.get("source_url"),
                row.get("notes"),
            ),
            query_name="dynamic_domain_context.upsert_reference",
        )
        writes += 1
    return writes


def apply_dynamic_domain_context_migration(
    run_sql: RunSql,
    *,
    run_sql_many: RunSqlMany | None = None,  # reserved for interface parity
) -> dict[str, Any]:
    del run_sql_many
    seeded_rows = default_domain_reference_seed_rows()
    if migration_already_applied(run_sql):
        seed_count = upsert_domain_reference_seed_rows(run_sql, seeded_rows)
        references = load_domain_reference_rows(run_sql)
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "migration_id": MIGRATION_ID,
            "schema_version_before": latest_schema_version(run_sql),
            "schema_version_after": SCHEMA_VERSION_AFTER,
            "already_applied": True,
            "reference_seed_rows": seed_count,
            "reference_rows_after": len(references),
            "references": references,
        }

    before_schema_version = latest_schema_version(run_sql)
    for stmt in DYNAMIC_DOMAIN_CONTEXT_MIGRATION.statements:
        run_sql(stmt, (), query_name=f"schema_migrations.apply.{MIGRATION_ID}")

    seed_count = upsert_domain_reference_seed_rows(run_sql, seeded_rows)
    append_schema_version(run_sql, SCHEMA_VERSION_AFTER)

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "migration_id": MIGRATION_ID,
        "schema_version_before": before_schema_version,
        "schema_version_after": SCHEMA_VERSION_AFTER,
        "reference_seed_rows": seed_count,
        "reference_rows_after": _reference_count(run_sql),
        "references": load_domain_reference_rows(run_sql),
    }
    receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / RECEIPT_SUBDIR
    receipt_files = write_dynamic_domain_context_receipt_bundle(payload, receipt_dir)
    record_schema_migration(
        run_sql,
        spec=DYNAMIC_DOMAIN_CONTEXT_MIGRATION,
        status="applied",
        schema_version_before=before_schema_version,
        schema_version_after=SCHEMA_VERSION_AFTER,
        notes="applied dynamic domain context tables and seeded reference rows",
        receipt_path=receipt_files["json"],
        payload=payload,
    )
    payload["receipt_files"] = receipt_files
    return payload


def apply_dynamic_domain_context_collation_hotfix(run_sql: RunSql) -> dict[str, Any]:
    if _migration_already_applied(run_sql, COLLATION_HOTFIX_MIGRATION_ID):
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "migration_id": COLLATION_HOTFIX_MIGRATION_ID,
            "schema_version_before": latest_schema_version(run_sql),
            "schema_version_after": COLLATION_HOTFIX_SCHEMA_VERSION_AFTER,
            "already_applied": True,
        }

    before_schema_version = latest_schema_version(run_sql)
    for stmt in DYNAMIC_DOMAIN_CONTEXT_COLLATION_HOTFIX.statements:
        run_sql(stmt, (), query_name=f"schema_migrations.apply.{COLLATION_HOTFIX_MIGRATION_ID}")
    append_schema_version(run_sql, COLLATION_HOTFIX_SCHEMA_VERSION_AFTER)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "migration_id": COLLATION_HOTFIX_MIGRATION_ID,
        "schema_version_before": before_schema_version,
        "schema_version_after": COLLATION_HOTFIX_SCHEMA_VERSION_AFTER,
        "applied_statements": list(DYNAMIC_DOMAIN_CONTEXT_COLLATION_HOTFIX.statements),
    }
    receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / RECEIPT_SUBDIR
    receipt_files = write_dynamic_domain_context_receipt_bundle(payload, receipt_dir)
    record_schema_migration(
        run_sql,
        spec=DYNAMIC_DOMAIN_CONTEXT_COLLATION_HOTFIX,
        status="applied",
        schema_version_before=before_schema_version,
        schema_version_after=COLLATION_HOTFIX_SCHEMA_VERSION_AFTER,
        notes="aligned dynamic_domain_observations.dynamic_run_id collation with dynamic_sessions",
        receipt_path=receipt_files["json"],
        payload=payload,
    )
    payload["receipt_files"] = receipt_files
    return payload


def write_dynamic_domain_context_receipt_bundle(payload: Mapping[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"dynamic_domain_context_{stamp}"
    files: dict[str, str] = {}

    json_path = output_dir / f"{stem}.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    files["json"] = str(json_path.resolve())

    refs = list(payload.get("references") or [])
    csv_path = output_dir / f"{stem}_references.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "package_name_scope",
            "domain_pattern",
            "match_type",
            "owner_class",
            "role_class",
            "confidence",
            "classification_basis",
            "source_label",
            "source_url",
            "notes",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in refs:
            writer.writerow({key: row.get(key) for key in fieldnames})
    files["references_csv"] = str(csv_path.resolve())

    txt_path = output_dir / f"{stem}.txt"
    txt_path.write_text(
        "\n".join(
            [
                f"migration_id: {payload.get('migration_id')}",
                f"schema_version_before: {payload.get('schema_version_before')}",
                f"schema_version_after: {payload.get('schema_version_after')}",
                f"reference_seed_rows: {payload.get('reference_seed_rows')}",
                f"reference_rows_after: {payload.get('reference_rows_after')}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    files["summary_txt"] = str(txt_path.resolve())
    return files


__all__ = [
    "DYNAMIC_DOMAIN_CONTEXT_MIGRATION",
    "DYNAMIC_DOMAIN_CONTEXT_COLLATION_HOTFIX",
    "COLLATION_HOTFIX_MIGRATION_ID",
    "COLLATION_HOTFIX_SCHEMA_VERSION_AFTER",
    "MIGRATION_ID",
    "SCHEMA_VERSION_AFTER",
    "apply_dynamic_domain_context_collation_hotfix",
    "apply_dynamic_domain_context_migration",
    "load_domain_reference_rows",
    "migration_already_applied",
    "upsert_domain_reference_seed_rows",
    "write_dynamic_domain_context_receipt_bundle",
]
