"""Additive migration and seed helpers for dynamic service signal taxonomy."""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_queries.canonical.schema import (
    CREATE_DYNAMIC_SERVICE_SIGNAL_MAP,
    CREATE_DYNAMIC_SIGNAL_CATALOG,
)
from scytaledroid.DynamicAnalysis.service_signals import (
    default_service_signal_map_seed_rows,
    default_signal_catalog_seed_rows,
)

from .schema_migration_registry import (
    MigrationSpec,
    append_schema_version,
    latest_schema_version,
    record_schema_migration,
)

RunSql = Callable[..., Any]
_REPO_ROOT = Path(__file__).resolve().parents[3]
RECEIPT_SUBDIR = "dynamic_service_signals"
MIGRATION_ID = "20260615_dynamic_service_signal_tables_v1"
SCHEMA_VERSION_AFTER = "0.3.11-dynamic-service-signals"

DYNAMIC_SERVICE_SIGNAL_MIGRATION = MigrationSpec(
    migration_id=MIGRATION_ID,
    migration_name="Dynamic service signal taxonomy and service-signal map tables",
    schema_version_before="0.3.10-dynamic-service-context",
    schema_version_after=SCHEMA_VERSION_AFTER,
    statements=(
        CREATE_DYNAMIC_SIGNAL_CATALOG.strip(),
        CREATE_DYNAMIC_SERVICE_SIGNAL_MAP.strip(),
    ),
    description="Adds DB-backed privacy/security/context signal taxonomy on top of dynamic service context.",
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


def _signal_count(run_sql: RunSql) -> int:
    row = run_sql(
        "SELECT COUNT(*) AS n FROM dynamic_signal_catalog WHERE is_active = 1",
        (),
        fetch="one",
        dictionary=True,
        query_name="dynamic_service_signals.signal_count",
    ) or {}
    return int(row.get("n") or 0) if isinstance(row, Mapping) else int(row[0] or 0)


def _map_count(run_sql: RunSql) -> int:
    row = run_sql(
        "SELECT COUNT(*) AS n FROM dynamic_service_signal_map WHERE is_active = 1",
        (),
        fetch="one",
        dictionary=True,
        query_name="dynamic_service_signals.map_count",
    ) or {}
    return int(row.get("n") or 0) if isinstance(row, Mapping) else int(row[0] or 0)


def _load_signal_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    rows = run_sql(
        """
        SELECT
          signal_key,
          display_name,
          signal_family,
          focus_area,
          severity_hint,
          description,
          analyst_guidance,
          source_label,
          source_url,
          notes
        FROM dynamic_signal_catalog
        WHERE is_active = 1
        ORDER BY focus_area, severity_hint, signal_key
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic_service_signals.load_signals",
    ) or []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _load_service_signal_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    rows = run_sql(
        """
        SELECT
          dsc.service_key,
          dsg.signal_key,
          dssm.signal_strength,
          dssm.confidence,
          dssm.rationale,
          dssm.source_label,
          dssm.source_url,
          dssm.notes
        FROM dynamic_service_signal_map dssm
        JOIN dynamic_service_catalog dsc
          ON dsc.service_id = dssm.service_id
        JOIN dynamic_signal_catalog dsg
          ON dsg.signal_id = dssm.signal_id
        WHERE dssm.is_active = 1
          AND dsc.is_active = 1
          AND dsg.is_active = 1
        ORDER BY dsc.service_key, dsg.signal_key
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic_service_signals.load_maps",
    ) or []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _upsert_signal_rows(run_sql: RunSql, rows: list[Mapping[str, Any]]) -> int:
    sql = """
        INSERT INTO dynamic_signal_catalog (
          signal_key,
          display_name,
          signal_family,
          focus_area,
          severity_hint,
          description,
          analyst_guidance,
          source_label,
          source_url,
          notes,
          is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1)
        ON DUPLICATE KEY UPDATE
          display_name = VALUES(display_name),
          signal_family = VALUES(signal_family),
          focus_area = VALUES(focus_area),
          severity_hint = VALUES(severity_hint),
          description = VALUES(description),
          analyst_guidance = VALUES(analyst_guidance),
          source_label = VALUES(source_label),
          source_url = VALUES(source_url),
          notes = VALUES(notes),
          is_active = VALUES(is_active)
    """
    count = 0
    for row in rows:
        run_sql(
            sql,
            (
                row.get("signal_key"),
                row.get("display_name"),
                row.get("signal_family"),
                row.get("focus_area"),
                row.get("severity_hint"),
                row.get("description"),
                row.get("analyst_guidance"),
                row.get("source_label"),
                row.get("source_url"),
                row.get("notes"),
            ),
            query_name="dynamic_service_signals.upsert_signal",
        )
        count += 1
    return count


def _upsert_service_signal_rows(run_sql: RunSql, rows: list[Mapping[str, Any]]) -> int:
    sql = """
        INSERT INTO dynamic_service_signal_map (
          service_id,
          signal_id,
          signal_strength,
          confidence,
          rationale,
          source_label,
          source_url,
          notes,
          is_active
        ) VALUES (
          (SELECT service_id FROM dynamic_service_catalog WHERE service_key = %s LIMIT 1),
          (SELECT signal_id FROM dynamic_signal_catalog WHERE signal_key = %s LIMIT 1),
          %s, %s, %s, %s, %s, %s, 1
        )
        ON DUPLICATE KEY UPDATE
          signal_strength = VALUES(signal_strength),
          confidence = VALUES(confidence),
          rationale = VALUES(rationale),
          source_label = VALUES(source_label),
          source_url = VALUES(source_url),
          notes = VALUES(notes),
          is_active = VALUES(is_active)
    """
    count = 0
    for row in rows:
        run_sql(
            sql,
            (
                row.get("service_key"),
                row.get("signal_key"),
                row.get("signal_strength"),
                row.get("confidence"),
                row.get("rationale"),
                row.get("source_label"),
                row.get("source_url"),
                row.get("notes"),
            ),
            query_name="dynamic_service_signals.upsert_map",
        )
        count += 1
    return count


def apply_dynamic_service_signal_migration(run_sql: RunSql) -> dict[str, Any]:
    if not migration_already_applied(run_sql):
        before_schema_version = latest_schema_version(run_sql)
        for stmt in DYNAMIC_SERVICE_SIGNAL_MIGRATION.statements:
            run_sql(stmt, (), query_name=f"schema_migrations.apply.{MIGRATION_ID}")
        append_schema_version(run_sql, SCHEMA_VERSION_AFTER)
        migration_applied = True
    else:
        before_schema_version = latest_schema_version(run_sql)
        migration_applied = False

    signals_seeded = _upsert_signal_rows(run_sql, default_signal_catalog_seed_rows())
    service_maps_seeded = _upsert_service_signal_rows(run_sql, default_service_signal_map_seed_rows())

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "migration_id": MIGRATION_ID,
        "schema_version_before": before_schema_version,
        "schema_version_after": SCHEMA_VERSION_AFTER,
        "already_applied": not migration_applied,
        "signals_seeded": signals_seeded,
        "service_signal_maps_seeded": service_maps_seeded,
        "signal_rows_after": _signal_count(run_sql),
        "service_signal_map_rows_after": _map_count(run_sql),
        "signals": _load_signal_rows(run_sql),
        "service_signal_maps": _load_service_signal_rows(run_sql),
    }
    receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / RECEIPT_SUBDIR
    files = write_dynamic_service_signal_receipt_bundle(payload, receipt_dir)
    payload["receipt_files"] = files
    if migration_applied:
        record_schema_migration(
            run_sql,
            spec=DYNAMIC_SERVICE_SIGNAL_MIGRATION,
            status="applied",
            schema_version_before=before_schema_version,
            schema_version_after=SCHEMA_VERSION_AFTER,
            notes="applied dynamic service signal tables and seeded signal/service-map rows",
            receipt_path=files["json"],
            payload=payload,
        )
    return payload


def write_dynamic_service_signal_receipt_bundle(payload: Mapping[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"dynamic_service_signals_{stamp}"
    files: dict[str, str] = {}

    json_path = output_dir / f"{stem}.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    files["json"] = str(json_path.resolve())

    for key, filename, fieldnames in (
        (
            "signals",
            f"{stem}_signals.csv",
            [
                "signal_key",
                "display_name",
                "signal_family",
                "focus_area",
                "severity_hint",
                "description",
                "analyst_guidance",
                "source_label",
                "source_url",
                "notes",
            ],
        ),
        (
            "service_signal_maps",
            f"{stem}_service_signal_maps.csv",
            [
                "service_key",
                "signal_key",
                "signal_strength",
                "confidence",
                "rationale",
                "source_label",
                "source_url",
                "notes",
            ],
        ),
    ):
        path = output_dir / filename
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in payload.get(key) or []:
                if isinstance(row, Mapping):
                    writer.writerow({field: row.get(field) for field in fieldnames})
        files[key] = str(path.resolve())
    return files


__all__ = [
    "MIGRATION_ID",
    "SCHEMA_VERSION_AFTER",
    "apply_dynamic_service_signal_migration",
    "migration_already_applied",
    "write_dynamic_service_signal_receipt_bundle",
]
