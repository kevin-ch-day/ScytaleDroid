"""Read-only preflight and bounded apply support for runtime ``schema_version`` width hotfixes."""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .phase_b1_join_key_normalization import (
    _column_index_metadata,
    _column_value_stats,
    _current_column_metadata,
    _current_definition_clause,
    _run_view_recreate,
    _view_dependencies,
    migration_already_applied,
    migration_preview,
    write_phase_b1_apply_receipt,
)
from .schema_migration_registry import (
    append_schema_version,
    latest_schema_version,
    record_schema_migration,
    registered_migrations,
)

RunSql = Callable[..., Any]

_REPO_ROOT = Path(__file__).resolve().parents[3]

TARGET_WIDTH = 64
HOTFIX_SCHEMA_VERSION = "0.3.6-schema-version-width-hotfix"
RECEIPT_SUBDIR = "schema_version_width_hotfix"
STEM_PREFIX = "schema_version_width_hotfix"

TARGET_COLUMNS: tuple[dict[str, Any], ...] = (
    {
        "table": "static_analysis_sessions",
        "column": "schema_version",
        "target_type": "varchar",
        "target_width": TARGET_WIDTH,
        "writer_dependencies": "static session shell upsert and refresh",
        "notes": "session-level execution spine header",
    },
    {
        "table": "static_analysis_runs",
        "column": "schema_version",
        "target_type": "varchar",
        "target_width": TARGET_WIDTH,
        "writer_dependencies": "static run persistence",
        "notes": "package-level canonical static run rows",
    },
    {
        "table": "dynamic_sessions",
        "column": "schema_version",
        "target_type": "varchar",
        "target_width": TARGET_WIDTH,
        "writer_dependencies": "dynamic session persistence",
        "notes": "dynamic execution spine rows",
    },
    {
        "table": "runs",
        "column": "schema_version",
        "target_type": "varchar",
        "target_width": TARGET_WIDTH,
        "writer_dependencies": "legacy compatibility writer bridge",
        "notes": "legacy compatibility runtime rows",
    },
)


def target_columns() -> tuple[dict[str, Any], ...]:
    return TARGET_COLUMNS


def _registered_migration(migration_id: str):
    for spec in registered_migrations():
        if spec.migration_id == migration_id:
            return spec
    raise KeyError(migration_id)


def planned_alter_sql() -> str:
    lines = [
        "-- Schema-version width hotfix planned ALTER SQL (dry-run only; do not apply without review)",
        "-- Scope: runtime base-table schema_version width only",
        "",
    ]
    for spec in TARGET_COLUMNS:
        lines.append(f"-- {spec['table']}.{spec['column']}")
        lines.append(
            f"ALTER TABLE `{spec['table']}` "
            f"MODIFY COLUMN `{spec['column']}` varchar({int(spec['target_width'])});"
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _build_required_alter_statements(run_sql: RunSql) -> list[dict[str, str]]:
    statements: list[dict[str, str]] = []
    for spec in TARGET_COLUMNS:
        table_name = str(spec["table"])
        column_name = str(spec["column"])
        current = _current_column_metadata(run_sql, table_name, column_name)
        current_width = int(current.get("character_maximum_length") or 0)
        current_type = str(current.get("column_type") or "").lower()
        expected_type = f"varchar({int(spec['target_width'])})"
        if current_width == int(spec["target_width"]) and current_type == expected_type:
            continue
        live_spec = {
            "target_type": "varchar",
            "target_width": int(spec["target_width"]),
            "target_charset": str(current.get("character_set_name") or "utf8mb4"),
            "target_collation": str(current.get("collation_name") or "utf8mb4_general_ci"),
        }
        definition = _current_definition_clause(current, live_spec)
        statements.append(
            {
                "table": table_name,
                "column": column_name,
                "sql": f"ALTER TABLE `{table_name}` MODIFY COLUMN `{column_name}` {definition}",
            }
        )
    return statements


def required_alter_sql(run_sql: RunSql) -> str:
    statements = _build_required_alter_statements(run_sql)
    if not statements:
        return ""
    lines = [
        "-- Schema-version width hotfix required ALTER SQL",
        "-- Only columns whose width differs from the runtime contract are included.",
        "",
    ]
    for row in statements:
        lines.append(f"-- {row['table']}.{row['column']}")
        lines.append(str(row["sql"]).rstrip(";") + ";")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _candidate_schema_version_length(run_sql: RunSql) -> int:
    live = latest_schema_version(run_sql) or ""
    return len(live)


def collect_schema_version_width_hotfix_preflight(run_sql: RunSql) -> dict[str, Any]:
    live_schema_version = latest_schema_version(run_sql)
    candidate_length = _candidate_schema_version_length(run_sql)
    columns: list[dict[str, Any]] = []
    width_checks: list[dict[str, Any]] = []
    view_dependency_rows: list[dict[str, Any]] = []
    views_requiring_recreate: set[str] = set()
    max_current_stored_len = 0
    values_gt_64_total = 0

    for spec in TARGET_COLUMNS:
        table_name = str(spec["table"])
        column_name = str(spec["column"])
        current = _current_column_metadata(run_sql, table_name, column_name)
        stats = _column_value_stats(run_sql, table_name, column_name)
        indexes = _column_index_metadata(run_sql, table_name, column_name)
        views = _view_dependencies(run_sql, table_name, column_name)
        for view_name in views:
            views_requiring_recreate.add(view_name)
            view_dependency_rows.append(
                {
                    "table": table_name,
                    "column": column_name,
                    "view_name": view_name,
                }
            )
        max_observed_length = int(stats.get("max_observed_length") or 0)
        max_current_stored_len = max(max_current_stored_len, max_observed_length)
        values_gt_64 = 1 if max_observed_length > TARGET_WIDTH else 0
        values_gt_64_total += values_gt_64
        width_checks.append(
            {
                "table": table_name,
                "column": column_name,
                "max_observed_length": max_observed_length,
                "target_width": TARGET_WIDTH,
                "fits_target_width": "yes" if max_observed_length <= TARGET_WIDTH else "no",
            }
        )
        columns.append(
            {
                "table": table_name,
                "column": column_name,
                "current_type": current.get("column_type"),
                "current_charset": current.get("character_set_name"),
                "current_collation": current.get("collation_name"),
                "current_width": int(current.get("character_maximum_length") or 0),
                "target_type": f"varchar({TARGET_WIDTH})",
                "target_charset": current.get("character_set_name"),
                "target_collation": current.get("collation_name"),
                "target_width": TARGET_WIDTH,
                "nullable": current.get("is_nullable"),
                "default": current.get("column_default"),
                "indexed": "yes" if indexes else "no",
                "index_names": ", ".join(str(row.get("index_name") or "") for row in indexes if str(row.get("index_name") or "")),
                "row_count": int(stats.get("row_count") or 0),
                "null_count": int(stats.get("null_count") or 0),
                "distinct_count": int(stats.get("distinct_count") or 0),
                "max_observed_length": max_observed_length,
                "view_dependencies": ", ".join(views),
                "writer_dependencies": spec["writer_dependencies"],
                "needs_width_change": "yes" if int(current.get("character_maximum_length") or 0) != TARGET_WIDTH else "no",
                "notes": spec.get("notes") or "",
            }
        )

    planned_sql = required_alter_sql(run_sql)
    preview = migration_preview("20260614_schema_version_width_hotfix_v1")
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "live_schema_version": live_schema_version,
        "live_schema_version_length": candidate_length,
        "hotfix_schema_version_after": HOTFIX_SCHEMA_VERSION,
        "hotfix_schema_version_after_length": len(HOTFIX_SCHEMA_VERSION),
        "target_column_count": len(TARGET_COLUMNS),
        "max_current_stored_schema_version_length": max_current_stored_len,
        "values_gt_64_total": values_gt_64_total,
        "views_requiring_recreate_count": len(views_requiring_recreate),
        "required_alter_statement_count": len(_build_required_alter_statements(run_sql)),
        "planned_alter_generated": bool(planned_sql),
        "preflight_clean": candidate_length <= TARGET_WIDTH and values_gt_64_total == 0 and len(columns) == len(TARGET_COLUMNS),
    }
    return {
        "summary": summary,
        "columns": columns,
        "width_checks": width_checks,
        "view_dependencies": view_dependency_rows,
        "views_requiring_recreate": sorted(views_requiring_recreate),
        "planned_alter_sql": planned_sql,
        "migration_registry_preview": preview,
    }


def write_schema_version_width_hotfix_preflight_bundle(
    report: Mapping[str, Any],
    output_dir: Path,
    *,
    stem: str,
) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}

    json_path = output_dir / f"{stem}_preflight.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    files["json"] = str(json_path.resolve())

    csv_payloads = {
        f"{stem}_columns.csv": report.get("columns") or [],
        f"{stem}_width_checks.csv": report.get("width_checks") or [],
        f"{stem}_view_dependencies.csv": report.get("view_dependencies") or [],
    }
    for filename, rows in csv_payloads.items():
        path = output_dir / filename
        row_list = list(rows)
        if not row_list:
            path.write_text("", encoding="utf-8")
            files[filename] = str(path.resolve())
            continue
        fieldnames: list[str] = []
        for row in row_list:
            if not isinstance(row, Mapping):
                continue
            for key in row.keys():
                if key not in fieldnames:
                    fieldnames.append(str(key))
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in row_list:
                writer.writerow({key: row.get(key) for key in fieldnames})
        files[filename] = str(path.resolve())

    sql_path = output_dir / f"{stem}_planned_alter.sql"
    sql_path.write_text(str(report.get("planned_alter_sql") or ""), encoding="utf-8")
    files["planned_sql"] = str(sql_path.resolve())
    return files


@dataclass(frozen=True)
class SchemaVersionWidthHotfixApplyResult:
    applied: bool
    altered_column_count: int
    altered_tables: tuple[str, ...]
    receipt_path: str


def apply_schema_version_width_hotfix(run_sql: RunSql) -> SchemaVersionWidthHotfixApplyResult:
    migration_id = "20260614_schema_version_width_hotfix_v1"
    spec = _registered_migration(migration_id)
    preflight = collect_schema_version_width_hotfix_preflight(run_sql)
    summary = preflight.get("summary") or {}
    if not bool(summary.get("preflight_clean")):
        raise ValueError("schema-version width hotfix preflight is not clean; refusing apply")
    statements = _build_required_alter_statements(run_sql)
    if migration_already_applied(run_sql, migration_id):
        return SchemaVersionWidthHotfixApplyResult(applied=False, altered_column_count=0, altered_tables=(), receipt_path="")

    before_schema_version = latest_schema_version(run_sql) or spec.schema_version_before
    altered_tables: list[str] = []
    try:
        for row in statements:
            altered_tables.append(str(row["table"]))
            run_sql(str(row["sql"]), (), query_name=f"schema_migrations.apply.{migration_id}")
        view_recreate = _run_view_recreate()
        if int(view_recreate.get("returncode", 1)) != 0:
            raise RuntimeError(
                "view recreation failed after ALTERs: "
                + str(view_recreate.get("stderr_tail") or view_recreate.get("stdout_tail") or "unknown error")
            )
        after_preflight = collect_schema_version_width_hotfix_preflight(run_sql)
        if not bool((after_preflight.get("summary") or {}).get("preflight_clean")):
            raise RuntimeError("schema-version width hotfix after-state preflight not clean")

        payload = {
            "mode": "apply",
            "generated_at": datetime.now(UTC).isoformat(),
            "migration_id": migration_id,
            "schema_version_before": before_schema_version,
            "schema_version_after": spec.schema_version_after,
            "altered_column_count": len(statements),
            "altered_tables": sorted(set(altered_tables)),
            "before_preflight_summary": summary,
            "after_preflight_summary": after_preflight.get("summary") or {},
            "view_recreate": view_recreate,
            "applied_statements": statements,
        }
        receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / RECEIPT_SUBDIR
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{STEM_PREFIX}_{stamp}"
        receipt = write_phase_b1_apply_receipt(receipt_dir, stem=stem, payload=payload)
        record_schema_migration(
            run_sql,
            spec=spec,
            status="applied",
            schema_version_before=before_schema_version,
            schema_version_after=spec.schema_version_after,
            notes="manual schema-version width hotfix for runtime base tables",
            receipt_path=receipt,
            payload={
                "altered_column_count": len(statements),
                "altered_tables": sorted(set(altered_tables)),
                "view_recreate_returncode": int(view_recreate.get("returncode") or 0),
            },
        )
        append_schema_version(run_sql, spec.schema_version_after)
        return SchemaVersionWidthHotfixApplyResult(
            applied=True,
            altered_column_count=len(statements),
            altered_tables=tuple(sorted(set(altered_tables))),
            receipt_path=receipt,
        )
    except Exception as exc:
        receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / RECEIPT_SUBDIR
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{STEM_PREFIX}_{stamp}"
        receipt = write_phase_b1_apply_receipt(
            receipt_dir,
            stem=stem,
            payload={
                "mode": "apply_failed",
                "generated_at": datetime.now(UTC).isoformat(),
                "migration_id": migration_id,
                "schema_version_before": before_schema_version,
                "error": f"{type(exc).__name__}: {exc}",
                "attempted_statements": statements,
            },
        )
        try:
            record_schema_migration(
                run_sql,
                spec=spec,
                status="failed",
                schema_version_before=before_schema_version,
                schema_version_after=spec.schema_version_after,
                notes=f"manual schema-version width hotfix failed: {type(exc).__name__}: {exc}",
                receipt_path=receipt,
            )
        except Exception:
            pass
        raise


__all__ = [
    "HOTFIX_SCHEMA_VERSION",
    "RECEIPT_SUBDIR",
    "STEM_PREFIX",
    "SchemaVersionWidthHotfixApplyResult",
    "TARGET_COLUMNS",
    "TARGET_WIDTH",
    "apply_schema_version_width_hotfix",
    "collect_schema_version_width_hotfix_preflight",
    "planned_alter_sql",
    "required_alter_sql",
    "target_columns",
    "write_schema_version_width_hotfix_preflight_bundle",
]
