"""Additive migration and seed helpers for dynamic service/provider context."""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_queries.canonical.schema import (
    CREATE_DYNAMIC_SERVICE_CATALOG,
    CREATE_DYNAMIC_SERVICE_DOMAIN_MAP,
)
from scytaledroid.DynamicAnalysis.service_context import (
    default_service_catalog_seed_rows,
    default_service_domain_map_seed_rows,
)

from .schema_migration_registry import (
    MigrationSpec,
    append_schema_version,
    latest_schema_version,
    record_schema_migration,
)

RunSql = Callable[..., Any]
_REPO_ROOT = Path(__file__).resolve().parents[3]
RECEIPT_SUBDIR = "dynamic_service_context"
MIGRATION_ID = "20260615_dynamic_service_context_tables_v1"
SCHEMA_VERSION_AFTER = "0.3.10-dynamic-service-context"

DYNAMIC_SERVICE_CONTEXT_MIGRATION = MigrationSpec(
    migration_id=MIGRATION_ID,
    migration_name="Dynamic service context catalog and domain map tables",
    schema_version_before="0.3.9-dynamic-domain-context-collation-hotfix",
    schema_version_after=SCHEMA_VERSION_AFTER,
    statements=(
        CREATE_DYNAMIC_SERVICE_CATALOG.strip(),
        CREATE_DYNAMIC_SERVICE_DOMAIN_MAP.strip(),
    ),
    description="Adds DB-backed provider/service catalog context and domain-to-service mappings for dynamic traffic interpretation.",
    apply_mode="manual_script",
    stage="dynamic_context",
)


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


def _service_count(run_sql: RunSql) -> int:
    row = run_sql(
        "SELECT COUNT(*) AS n FROM dynamic_service_catalog WHERE is_active = 1",
        (),
        fetch="one",
        dictionary=True,
        query_name="dynamic_service_context.service_count",
    ) or {}
    return int(row.get("n") or 0) if isinstance(row, Mapping) else int(row[0] or 0)


def _domain_map_count(run_sql: RunSql) -> int:
    row = run_sql(
        "SELECT COUNT(*) AS n FROM dynamic_service_domain_map WHERE is_active = 1",
        (),
        fetch="one",
        dictionary=True,
        query_name="dynamic_service_context.domain_map_count",
    ) or {}
    return int(row.get("n") or 0) if isinstance(row, Mapping) else int(row[0] or 0)


def _load_service_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    rows = run_sql(
        """
        SELECT
          service_key,
          display_name,
          owner_name,
          owner_class,
          service_category,
          primary_use_case,
          documentation_url,
          privacy_policy_url,
          source_label,
          source_url,
          confidence,
          notes
        FROM dynamic_service_catalog
        WHERE is_active = 1
        ORDER BY owner_class, service_category, service_key
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic_service_context.load_services",
    ) or []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _load_domain_map_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    rows = run_sql(
        """
        SELECT
          dsc.service_key,
          dsdm.package_name_scope,
          dsdm.domain_pattern,
          dsdm.match_type,
          dsdm.role_class,
          dsdm.source_label,
          dsdm.source_url,
          dsdm.confidence,
          dsdm.notes
        FROM dynamic_service_domain_map dsdm
        JOIN dynamic_service_catalog dsc
          ON dsc.service_id = dsdm.service_id
        WHERE dsdm.is_active = 1
          AND dsc.is_active = 1
        ORDER BY dsc.service_key, dsdm.package_name_scope, dsdm.match_type, dsdm.domain_pattern
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic_service_context.load_domain_maps",
    ) or []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _upsert_service_rows(run_sql: RunSql, rows: list[Mapping[str, Any]]) -> int:
    sql = """
        INSERT INTO dynamic_service_catalog (
          service_key,
          display_name,
          owner_name,
          owner_class,
          service_category,
          primary_use_case,
          documentation_url,
          privacy_policy_url,
          source_label,
          source_url,
          confidence,
          notes,
          is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1)
        ON DUPLICATE KEY UPDATE
          display_name = VALUES(display_name),
          owner_name = VALUES(owner_name),
          owner_class = VALUES(owner_class),
          service_category = VALUES(service_category),
          primary_use_case = VALUES(primary_use_case),
          documentation_url = VALUES(documentation_url),
          privacy_policy_url = VALUES(privacy_policy_url),
          source_label = VALUES(source_label),
          source_url = VALUES(source_url),
          confidence = VALUES(confidence),
          notes = VALUES(notes),
          is_active = VALUES(is_active)
    """
    count = 0
    for row in rows:
        run_sql(
            sql,
            (
                row.get("service_key"),
                row.get("display_name"),
                row.get("owner_name"),
                row.get("owner_class"),
                row.get("service_category"),
                row.get("primary_use_case"),
                row.get("documentation_url"),
                row.get("privacy_policy_url"),
                row.get("source_label"),
                row.get("source_url"),
                row.get("confidence"),
                row.get("notes"),
            ),
            query_name="dynamic_service_context.upsert_service",
        )
        count += 1
    return count


def _upsert_domain_map_rows(run_sql: RunSql, rows: list[Mapping[str, Any]]) -> int:
    sql = """
        INSERT INTO dynamic_service_domain_map (
          service_id,
          package_name_scope,
          domain_pattern,
          match_type,
          role_class,
          source_label,
          source_url,
          confidence,
          notes,
          is_active
        ) VALUES (
          (SELECT service_id FROM dynamic_service_catalog WHERE service_key = %s LIMIT 1),
          %s, %s, %s, %s, %s, %s, %s, %s, 1
        )
        ON DUPLICATE KEY UPDATE
          role_class = VALUES(role_class),
          source_label = VALUES(source_label),
          source_url = VALUES(source_url),
          confidence = VALUES(confidence),
          notes = VALUES(notes),
          is_active = VALUES(is_active)
    """
    count = 0
    for row in rows:
        run_sql(
            sql,
            (
                row.get("service_key"),
                row.get("package_name_scope"),
                row.get("domain_pattern"),
                row.get("match_type"),
                row.get("role_class"),
                row.get("source_label"),
                row.get("source_url"),
                row.get("confidence"),
                row.get("notes"),
            ),
            query_name="dynamic_service_context.upsert_domain_map",
        )
        count += 1
    return count


def apply_dynamic_service_context_migration(run_sql: RunSql) -> dict[str, Any]:
    if not migration_already_applied(run_sql):
        before_schema_version = latest_schema_version(run_sql)
        for stmt in DYNAMIC_SERVICE_CONTEXT_MIGRATION.statements:
            run_sql(stmt, (), query_name=f"schema_migrations.apply.{MIGRATION_ID}")
        append_schema_version(run_sql, SCHEMA_VERSION_AFTER)
        migration_applied = True
    else:
        before_schema_version = latest_schema_version(run_sql)
        migration_applied = False

    services_seeded = _upsert_service_rows(run_sql, default_service_catalog_seed_rows())
    domain_maps_seeded = _upsert_domain_map_rows(run_sql, default_service_domain_map_seed_rows())

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "migration_id": MIGRATION_ID,
        "schema_version_before": before_schema_version,
        "schema_version_after": SCHEMA_VERSION_AFTER,
        "already_applied": not migration_applied,
        "services_seeded": services_seeded,
        "domain_maps_seeded": domain_maps_seeded,
        "service_rows_after": _service_count(run_sql),
        "domain_map_rows_after": _domain_map_count(run_sql),
        "services": _load_service_rows(run_sql),
        "domain_maps": _load_domain_map_rows(run_sql),
    }
    receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / RECEIPT_SUBDIR
    files = write_dynamic_service_context_receipt_bundle(payload, receipt_dir)
    payload["receipt_files"] = files
    if migration_applied:
        record_schema_migration(
            run_sql,
            spec=DYNAMIC_SERVICE_CONTEXT_MIGRATION,
            status="applied",
            schema_version_before=before_schema_version,
            schema_version_after=SCHEMA_VERSION_AFTER,
            notes="applied dynamic service context tables and seeded service/domain-map rows",
            receipt_path=files["json"],
            payload=payload,
        )
    return payload


def write_dynamic_service_context_receipt_bundle(payload: Mapping[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"dynamic_service_context_{stamp}"
    files: dict[str, str] = {}

    json_path = output_dir / f"{stem}.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    files["json"] = str(json_path.resolve())

    services_csv = output_dir / f"{stem}_services.csv"
    with services_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "service_key",
                "display_name",
                "owner_name",
                "owner_class",
                "service_category",
                "primary_use_case",
                "documentation_url",
                "privacy_policy_url",
                "source_label",
                "source_url",
                "confidence",
                "notes",
            ],
        )
        writer.writeheader()
        for row in payload.get("services") or []:
            if isinstance(row, Mapping):
                writer.writerow({key: row.get(key) for key in writer.fieldnames})
    files["services_csv"] = str(services_csv.resolve())

    domain_maps_csv = output_dir / f"{stem}_domain_maps.csv"
    with domain_maps_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "service_key",
                "package_name_scope",
                "domain_pattern",
                "match_type",
                "role_class",
                "source_label",
                "source_url",
                "confidence",
                "notes",
            ],
        )
        writer.writeheader()
        for row in payload.get("domain_maps") or []:
            if isinstance(row, Mapping):
                writer.writerow({key: row.get(key) for key in writer.fieldnames})
    files["domain_maps_csv"] = str(domain_maps_csv.resolve())

    return files


__all__ = [
    "MIGRATION_ID",
    "SCHEMA_VERSION_AFTER",
    "apply_dynamic_service_context_migration",
    "migration_already_applied",
    "write_dynamic_service_context_receipt_bundle",
]
