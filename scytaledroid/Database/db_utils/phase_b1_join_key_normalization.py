"""Read-only preflight and planned SQL generation for Phase B1 join-key normalization."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .artifact_registry_typed_linkage import collect_artifact_registry_typed_linkage_audit
from .phase_a_read_parity import collect_phase_a_read_parity
from .schema_migration_registry import (
    append_schema_version,
    latest_rows_by_migration,
    latest_schema_version,
    record_schema_migration,
    registered_migrations,
)

RunSql = Callable[..., Any]

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _rows(run_sql: RunSql, sql: str, params: Sequence[Any] | None = None, *, query_name: str) -> list[dict[str, Any]]:
    out = run_sql(sql, tuple(params or ()), fetch="all", dictionary=True, query_name=query_name) or []
    return [dict(row) for row in out if isinstance(row, Mapping)]


def _row(run_sql: RunSql, sql: str, params: Sequence[Any] | None = None, *, query_name: str) -> dict[str, Any]:
    out = run_sql(sql, tuple(params or ()), fetch="one", dictionary=True, query_name=query_name) or {}
    return dict(out) if isinstance(out, Mapping) else {}


TARGET_CHARSET = "utf8mb4"
TARGET_COLLATION = "utf8mb4_unicode_ci"
TARGET_SESSION_STAMP_WIDTH = 128


TARGET_COLUMNS: tuple[dict[str, Any], ...] = (
    {
        "table": "static_analysis_sessions",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "static session shell upsert; static session refresh; session health rollups",
        "notes": "canonical session header",
    },
    {
        "table": "static_analysis_runs",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "static run persistence; static run refresh",
        "notes": "execution spine child session key",
    },
    {
        "table": "static_session_run_links",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "session-run link writes; session summary refresh",
        "notes": "latin1 debt; highest-risk B1 conversion",
    },
    {
        "table": "static_findings_summary",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "static findings summary persistence",
        "notes": "short-width child session key",
    },
    {
        "table": "static_string_summary",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "static string summary persistence",
        "notes": "short-width child session key",
    },
    {
        "table": "apps",
        "column": "package_name",
        "target_type": "varchar",
        "target_width": 255,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "inventory sync; catalog hygiene; app identity writes",
        "notes": "already canonical in live DB",
    },
    {
        "table": "apk_sets",
        "column": "package_name",
        "target_type": "varchar",
        "target_width": 255,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "APK set persistence; harvest-to-library linkage",
        "notes": "mixed package_name collation",
    },
    {
        "table": "harvest_apk_observations",
        "column": "package_name",
        "target_type": "varchar",
        "target_width": 255,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "harvest observation persistence",
        "notes": "mixed package_name collation",
    },
    {
        "table": "analysis_dynamic_cohort_status",
        "column": "package_name_lc",
        "target_type": "varchar",
        "target_width": 255,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "dynamic readiness and cohort reporting scripts",
        "notes": "derived lowercase helper; included but not yet a broad canonical family",
    },
    {
        "table": "dynamic_sessions",
        "column": "profile_key",
        "target_type": "varchar",
        "target_width": 64,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "dynamic session persistence",
        "notes": "currently all NULL in live data",
    },
    {
        "table": "static_analysis_runs",
        "column": "profile_key",
        "target_type": "varchar",
        "target_width": 64,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "static run persistence",
        "notes": "mixed profile_key collation",
    },
    {
        "table": "android_app_profiles",
        "column": "profile_key",
        "target_type": "varchar",
        "target_width": 64,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "app profile catalog maintenance",
        "notes": "already canonical in live DB",
    },
)


BACKLOG_SESSION_STAMP_TARGET_COLUMNS: tuple[dict[str, Any], ...] = (
    {
        "table": "risk_scores",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "permission posture score persistence; risk read-model refresh",
        "notes": "derived read-model session key",
    },
    {
        "table": "runs",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "legacy compatibility writer bridge",
        "notes": "legacy compatibility session key",
    },
    {
        "table": "static_dynload_events",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "dynamic-load/static event persistence",
        "notes": "empty in live DB; narrow child evidence key debt",
    },
    {
        "table": "static_fileproviders",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "provider/component persistence",
        "notes": "active evidence table; narrow child evidence key debt",
    },
    {
        "table": "static_provider_acl",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "provider ACL persistence",
        "notes": "active evidence table; narrow child evidence key debt",
    },
    {
        "table": "static_reflection_calls",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "reflection/static event persistence",
        "notes": "empty in live DB; narrow child evidence key debt",
    },
    {
        "table": "static_session_rollups",
        "column": "session_stamp",
        "target_type": "varchar",
        "target_width": 128,
        "target_charset": TARGET_CHARSET,
        "target_collation": TARGET_COLLATION,
        "writer_dependencies": "session rollup persistence; session dashboard refresh",
        "notes": "derived session rollup key",
    },
)


JOIN_PARITY_QUERIES: tuple[dict[str, str], ...] = (
    {
        "join_name": "static_sessions_to_links_by_session_stamp",
        "sql": """
            SELECT COUNT(*) AS join_count
            FROM static_analysis_sessions sas
            JOIN static_session_run_links ssrl
              ON CONVERT(sas.session_stamp USING utf8mb4) COLLATE utf8mb4_unicode_ci
               = CONVERT(ssrl.session_stamp USING utf8mb4) COLLATE utf8mb4_unicode_ci
        """,
    },
    {
        "join_name": "static_sessions_to_runs_by_session_stamp",
        "sql": """
            SELECT COUNT(*) AS join_count
            FROM static_analysis_sessions sas
            JOIN static_analysis_runs sar
              ON CONVERT(sas.session_stamp USING utf8mb4) COLLATE utf8mb4_unicode_ci
               = CONVERT(sar.session_stamp USING utf8mb4) COLLATE utf8mb4_unicode_ci
        """,
    },
    {
        "join_name": "static_runs_to_links_by_run_id_and_session_stamp",
        "sql": """
            SELECT COUNT(*) AS join_count
            FROM static_analysis_runs sar
            JOIN static_session_run_links ssrl
              ON sar.id = ssrl.static_run_id
             AND CONVERT(sar.session_stamp USING utf8mb4) COLLATE utf8mb4_unicode_ci
               = CONVERT(ssrl.session_stamp USING utf8mb4) COLLATE utf8mb4_unicode_ci
        """,
    },
    {
        "join_name": "apps_to_apk_sets_by_package_name",
        "sql": """
            SELECT COUNT(*) AS join_count
            FROM apps a
            JOIN apk_sets aps
              ON CONVERT(a.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci
               = CONVERT(aps.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci
        """,
    },
    {
        "join_name": "apps_to_harvest_observations_by_package_name",
        "sql": """
            SELECT COUNT(*) AS join_count
            FROM apps a
            JOIN harvest_apk_observations hao
              ON CONVERT(a.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci
               = CONVERT(hao.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci
        """,
    },
    {
        "join_name": "static_runs_to_profiles_by_profile_key",
        "sql": """
            SELECT COUNT(*) AS join_count
            FROM static_analysis_runs sar
            JOIN android_app_profiles ap
              ON CONVERT(sar.profile_key USING utf8mb4) COLLATE utf8mb4_unicode_ci
               = CONVERT(ap.profile_key USING utf8mb4) COLLATE utf8mb4_unicode_ci
        """,
    },
    {
        "join_name": "dynamic_sessions_to_profiles_by_profile_key",
        "sql": """
            SELECT COUNT(*) AS join_count
            FROM dynamic_sessions ds
            JOIN android_app_profiles ap
              ON CONVERT(ds.profile_key USING utf8mb4) COLLATE utf8mb4_unicode_ci
               = CONVERT(ap.profile_key USING utf8mb4) COLLATE utf8mb4_unicode_ci
        """,
    },
    {
        "join_name": "dynamic_sessions_to_artifact_registry_by_dynamic_uuid",
        "sql": """
            SELECT COUNT(*) AS join_count
            FROM dynamic_sessions ds
            JOIN artifact_registry ar
              ON CONVERT(ds.dynamic_run_id USING utf8mb4) COLLATE utf8mb4_unicode_ci
               = CONVERT(ar.dynamic_run_uuid USING utf8mb4) COLLATE utf8mb4_unicode_ci
            WHERE ar.run_type = 'dynamic'
        """,
    },
)


def target_columns() -> tuple[dict[str, Any], ...]:
    return TARGET_COLUMNS


def backlog_session_stamp_target_columns() -> tuple[dict[str, Any], ...]:
    return BACKLOG_SESSION_STAMP_TARGET_COLUMNS


def _find_target(table_name: str, column_name: str) -> dict[str, Any]:
    for spec in TARGET_COLUMNS:
        if spec["table"] == table_name and spec["column"] == column_name:
            return dict(spec)
    raise KeyError(f"Unknown B1 target column: {table_name}.{column_name}")


def _current_column_metadata(run_sql: RunSql, table_name: str, column_name: str) -> dict[str, Any]:
    return _row(
        run_sql,
        """
        SELECT
          table_name,
          column_name,
          column_type,
          is_nullable,
          column_default,
          character_set_name,
          collation_name,
          character_maximum_length,
          numeric_precision,
          column_key
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        """,
        (table_name, column_name),
        query_name="phase_b1_preflight.current_column_metadata",
    )


def _column_value_stats(run_sql: RunSql, table_name: str, column_name: str) -> dict[str, Any]:
    sql = (
        f"SELECT COUNT(*) AS row_count, "
        f"SUM(CASE WHEN `{column_name}` IS NULL THEN 1 ELSE 0 END) AS null_count, "
        f"COUNT(DISTINCT `{column_name}`) AS distinct_count, "
        f"MAX(CHAR_LENGTH(`{column_name}`)) AS max_observed_length "
        f"FROM `{table_name}`"
    )
    return _row(run_sql, sql, query_name="phase_b1_preflight.column_value_stats")


def _column_index_metadata(run_sql: RunSql, table_name: str, column_name: str) -> list[dict[str, Any]]:
    return _rows(
        run_sql,
        """
        SELECT index_name, non_unique, seq_in_index
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        ORDER BY index_name, seq_in_index
        """,
        (table_name, column_name),
        query_name="phase_b1_preflight.column_index_metadata",
    )


def _fk_involved(run_sql: RunSql, table_name: str, column_name: str) -> bool:
    row = _row(
        run_sql,
        """
        SELECT COUNT(*) AS fk_count
        FROM information_schema.key_column_usage
        WHERE table_schema = DATABASE()
          AND (
            (table_name = %s AND column_name = %s AND referenced_table_name IS NOT NULL)
            OR
            (referenced_table_name = %s AND referenced_column_name = %s)
          )
        """,
        (table_name, column_name, table_name, column_name),
        query_name="phase_b1_preflight.fk_involved",
    )
    return int(row.get("fk_count") or 0) > 0


def _view_dependencies(run_sql: RunSql, table_name: str, column_name: str) -> list[str]:
    rows = _rows(
        run_sql,
        """
        SELECT table_name AS view_name
        FROM information_schema.views
        WHERE table_schema = DATABASE()
          AND LOWER(COALESCE(view_definition, '')) LIKE CONCAT('%%', LOWER(%s), '%%')
          AND LOWER(COALESCE(view_definition, '')) LIKE CONCAT('%%', LOWER(%s), '%%')
        ORDER BY table_name
        """,
        (table_name, column_name),
        query_name="phase_b1_preflight.view_dependencies",
    )
    return [str(row.get("view_name") or "").strip() for row in rows if str(row.get("view_name") or "").strip()]


def _sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    text = str(value)
    return "'" + text.replace("\\", "\\\\").replace("'", "''") + "'"


def _current_definition_clause(current: Mapping[str, Any], spec: Mapping[str, Any]) -> str:
    type_decl = f"{spec['target_type']}({int(spec['target_width'])})"
    charset = str(spec["target_charset"])
    collation = str(spec["target_collation"])
    nullable = str(current.get("is_nullable") or "").strip().upper() == "YES"
    default = current.get("column_default")
    extra = str(current.get("extra") or "").strip()
    column_comment = str(current.get("column_comment") or "")

    parts = [type_decl, f"CHARACTER SET {charset}", f"COLLATE {collation}", "NULL" if nullable else "NOT NULL"]
    if nullable and (default is None or str(default).strip().upper() == "NULL"):
        parts.append("DEFAULT NULL")
    elif default is not None and str(default).strip().upper() != "NULL":
        parts.append(f"DEFAULT {_sql_literal(default)}")
    if extra:
        parts.append(extra)
    if column_comment:
        parts.append(f"COMMENT {_sql_literal(column_comment)}")
    return " ".join(parts)


def _normalized_expression(column_name: str) -> str:
    return f"LOWER(CONVERT(`{column_name}` USING utf8mb4) COLLATE utf8mb4_unicode_ci)"


def _duplicate_collapse_rows(
    run_sql: RunSql,
    table_name: str,
    column_name: str,
    *,
    sample_limit: int,
) -> list[dict[str, Any]]:
    normalized = _normalized_expression(column_name)
    sql = f"""
        SELECT
          {normalized} AS normalized_value,
          COUNT(*) AS row_count,
          COUNT(DISTINCT `{column_name}`) AS raw_distinct_count,
          GROUP_CONCAT(DISTINCT `{column_name}` ORDER BY `{column_name}` SEPARATOR ' || ') AS raw_values
        FROM `{table_name}`
        WHERE `{column_name}` IS NOT NULL
        GROUP BY {normalized}
        HAVING COUNT(DISTINCT `{column_name}`) > 1
        ORDER BY raw_distinct_count DESC, row_count DESC, normalized_value
        LIMIT %s
    """
    return _rows(
        run_sql,
        sql,
        (int(sample_limit),),
        query_name="phase_b1_preflight.duplicate_collapse_rows",
    )


def _duplicate_collapse_summary(run_sql: RunSql, table_name: str, column_name: str) -> dict[str, Any]:
    normalized = _normalized_expression(column_name)
    return _row(
        run_sql,
        f"""
        SELECT
          COUNT(*) AS nonnull_rows,
          COUNT(DISTINCT `{column_name}`) AS raw_distinct_count,
          COUNT(DISTINCT {normalized}) AS normalized_distinct_count
        FROM `{table_name}`
        WHERE `{column_name}` IS NOT NULL
        """,
        query_name="phase_b1_preflight.duplicate_collapse_summary",
    )


def _join_parity_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for spec in JOIN_PARITY_QUERIES:
        result = _row(run_sql, spec["sql"], query_name=f"phase_b1_preflight.join_parity.{spec['join_name']}")
        rows.append(
            {
                "join_name": spec["join_name"],
                "join_count": int(result.get("join_count") or 0),
                "sql": " ".join(spec["sql"].split()),
            }
        )
    return rows


def _planned_alter_sql_for_targets(
    targets: Sequence[Mapping[str, Any]],
    *,
    banner: str,
    note_lines: Sequence[str] = (),
) -> str:
    lines = [
        banner,
        "-- Target collation: utf8mb4_unicode_ci",
        "-- Target session_stamp width: VARCHAR(128)",
        "",
    ]
    for note in note_lines:
        lines.append(str(note))
    if note_lines:
        lines.append("")
    for spec in targets:
        table_name = str(spec["table"])
        column_name = str(spec["column"])
        target_width = int(spec["target_width"])
        target_type = str(spec["target_type"]).lower()
        target_charset = str(spec["target_charset"])
        target_collation = str(spec["target_collation"])
        target_decl = f"{target_type}({target_width})"
        lines.append(f"-- {table_name}.{column_name}")
        lines.append(
            f"ALTER TABLE `{table_name}` "
            f"MODIFY COLUMN `{column_name}` {target_decl} "
            f"CHARACTER SET {target_charset} COLLATE {target_collation};"
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def planned_alter_sql() -> str:
    return _planned_alter_sql_for_targets(
        TARGET_COLUMNS,
        banner="-- Phase B1 planned ALTER SQL (dry-run only; do not apply without review)",
    )


def planned_backlog_session_stamp_alter_sql() -> str:
    return _planned_alter_sql_for_targets(
        BACKLOG_SESSION_STAMP_TARGET_COLUMNS,
        banner="-- Phase B1 session-stamp backlog planned ALTER SQL (dry-run only; do not apply without review)",
        note_lines=("-- Scope: legacy/derived session_stamp backlog only",),
    )


def _build_required_alter_statements(run_sql: RunSql, targets: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    statements: list[dict[str, str]] = []
    for spec in targets:
        table_name = str(spec["table"])
        column_name = str(spec["column"])
        current = _current_column_metadata(run_sql, table_name, column_name)
        current_collation = str(current.get("collation_name") or "")
        current_width = int(current.get("character_maximum_length") or 0)
        current_type = str(current.get("column_type") or "").lower()
        expected_type = f"{str(spec['target_type']).lower()}({int(spec['target_width'])})"
        needs_change = (
            current_collation != str(spec["target_collation"])
            or current_width != int(spec["target_width"])
            or current_type != expected_type
        )
        if not needs_change:
            continue
        definition = _current_definition_clause(current, spec)
        statements.append(
            {
                "table": table_name,
                "column": column_name,
                "sql": f"ALTER TABLE `{table_name}` MODIFY COLUMN `{column_name}` {definition}",
            }
        )
    return statements


def build_required_alter_statements(run_sql: RunSql) -> list[dict[str, str]]:
    return _build_required_alter_statements(run_sql, TARGET_COLUMNS)


def build_required_backlog_session_stamp_alter_statements(run_sql: RunSql) -> list[dict[str, str]]:
    return _build_required_alter_statements(run_sql, BACKLOG_SESSION_STAMP_TARGET_COLUMNS)


def required_alter_sql(run_sql: RunSql) -> str:
    statements = build_required_alter_statements(run_sql)
    if not statements:
        return ""
    lines = [
        "-- Phase B1 required ALTER SQL (dry-run only; do not apply without review)",
        "-- Target collation: utf8mb4_unicode_ci",
        "-- Only columns whose live shape differs from the B1 contract are included.",
        "",
    ]
    for row in statements:
        lines.append(f"-- {row['table']}.{row['column']}")
        lines.append(str(row["sql"]).rstrip(";") + ";")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _registered_migration(migration_id: str):
    for spec in registered_migrations():
        if spec.migration_id == migration_id:
            return spec
    raise KeyError(migration_id)


def migration_preview(migration_id: str) -> dict[str, Any]:
    spec = _registered_migration(migration_id)
    return {
        "migration_id": spec.migration_id,
        "migration_name": spec.migration_name,
        "schema_version_before": spec.schema_version_before,
        "schema_version_after": spec.schema_version_after,
        "description": spec.description,
        "apply_mode": spec.apply_mode,
        "stage": spec.stage,
        "registered_statement_count": len(spec.statements),
        "checksum": spec.checksum,
    }


def migration_already_applied(run_sql: RunSql, migration_id: str) -> bool:
    latest = latest_rows_by_migration(run_sql).get(migration_id) or {}
    return str(latest.get("status") or "").strip().lower() == "applied"


def _run_view_recreate() -> dict[str, Any]:
    script = _REPO_ROOT / "scripts" / "db" / "recreate_web_consumer_views.py"
    proc = subprocess.run(
        [sys.executable, str(script), "recreate", "--layer", "full"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return {
        "returncode": int(proc.returncode),
        "stdout_tail": (proc.stdout or "")[-6000:],
        "stderr_tail": (proc.stderr or "")[-6000:],
    }


@dataclass(frozen=True)
class PhaseB1ApplyResult:
    applied: bool
    altered_column_count: int
    altered_tables: tuple[str, ...]
    receipt_path: str


def write_phase_b1_apply_receipt(output_dir: Path, *, stem: str, payload: Mapping[str, Any]) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{stem}_apply.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return str(path.resolve())


def _apply_join_key_normalization(
    run_sql: RunSql,
    *,
    migration_id: str,
    targets: Sequence[Mapping[str, Any]],
    expected_target_count: int,
    receipt_subdir: str,
    stem_prefix: str,
    preflight_collector: Callable[[RunSql], dict[str, Any]],
    statement_builder: Callable[[RunSql], list[dict[str, str]]],
    notes: str,
) -> PhaseB1ApplyResult:
    spec = _registered_migration(migration_id)
    before_preflight = preflight_collector(run_sql)
    before_summary = before_preflight.get("summary") or {}
    if not bool(before_summary.get("preflight_clean")):
        raise ValueError(f"{stem_prefix} preflight is not clean; refusing apply")
    if int(before_summary.get("target_column_count") or 0) != expected_target_count:
        raise ValueError(f"{stem_prefix} target column count mismatch; refusing apply")
    statements = statement_builder(run_sql)
    if migration_already_applied(run_sql, spec.migration_id):
        return PhaseB1ApplyResult(applied=False, altered_column_count=0, altered_tables=(), receipt_path="")

    before_schema_version = latest_schema_version(run_sql) or spec.schema_version_before
    before_typed_parity = collect_phase_a_read_parity(run_sql)
    before_registry = collect_artifact_registry_typed_linkage_audit(run_sql)
    altered_tables: list[str] = []
    try:
        for row in statements:
            altered_tables.append(str(row["table"]))
            run_sql(str(row["sql"]), (), query_name=f"schema_migrations.apply.{spec.migration_id}")
        view_recreate = _run_view_recreate()
        if int(view_recreate.get("returncode", 1)) != 0:
            raise RuntimeError(
                "view recreation failed after ALTERs: "
                + str(view_recreate.get("stderr_tail") or view_recreate.get("stdout_tail") or "unknown error")
            )
        after_preflight = preflight_collector(run_sql)
        after_typed_parity = collect_phase_a_read_parity(run_sql)
        after_registry = collect_artifact_registry_typed_linkage_audit(run_sql)
        before_join = {str(row["join_name"]): int(row["join_count"]) for row in before_preflight.get("join_parity_before") or []}
        after_join = {str(row["join_name"]): int(row["join_count"]) for row in after_preflight.get("join_parity_before") or []}
        if before_join != after_join:
            raise RuntimeError(f"{stem_prefix} join parity changed after apply")
        if not bool((after_preflight.get("summary") or {}).get("preflight_clean")):
            raise RuntimeError(f"{stem_prefix} after-state preflight not clean")
        if not bool((after_typed_parity.get("summary") or {}).get("parity_clean")):
            raise RuntimeError("phase-a typed read parity became unclean after apply")
        if int((after_registry.get("fallback_needed_rows") or 0)) != 0:
            raise RuntimeError("artifact registry fallback-needed rows appeared after apply")

        payload = {
            "mode": "apply",
            "generated_at": datetime.now(UTC).isoformat(),
            "migration_id": spec.migration_id,
            "schema_version_before": before_schema_version,
            "schema_version_after": spec.schema_version_after,
            "altered_column_count": len(statements),
            "altered_tables": sorted(set(altered_tables)),
            "before_preflight_summary": before_summary,
            "after_preflight_summary": after_preflight.get("summary") or {},
            "before_join_parity": before_preflight.get("join_parity_before") or [],
            "after_join_parity": after_preflight.get("join_parity_before") or [],
            "before_typed_parity_summary": before_typed_parity.get("summary") or {},
            "after_typed_parity_summary": after_typed_parity.get("summary") or {},
            "before_artifact_registry_summary": before_registry,
            "after_artifact_registry_summary": after_registry,
            "view_recreate": view_recreate,
            "applied_statements": statements,
        }
        receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / receipt_subdir
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{stem_prefix}_{stamp}"
        receipt = write_phase_b1_apply_receipt(receipt_dir, stem=stem, payload=payload)
        record_schema_migration(
            run_sql,
            spec=spec,
            status="applied",
            schema_version_before=before_schema_version,
            schema_version_after=spec.schema_version_after,
            notes=notes,
            receipt_path=receipt,
            payload={
                "altered_column_count": len(statements),
                "altered_tables": sorted(set(altered_tables)),
                "view_recreate_returncode": int(view_recreate.get("returncode") or 0),
            },
        )
        append_schema_version(run_sql, spec.schema_version_after)
        return PhaseB1ApplyResult(
            applied=True,
            altered_column_count=len(statements),
            altered_tables=tuple(sorted(set(altered_tables))),
            receipt_path=receipt,
        )
    except Exception as exc:
        receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / receipt_subdir
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{stem_prefix}_{stamp}"
        receipt = write_phase_b1_apply_receipt(
            receipt_dir,
            stem=stem,
            payload={
                "mode": "apply_failed",
                "generated_at": datetime.now(UTC).isoformat(),
                "migration_id": spec.migration_id,
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
                notes=f"{notes} failed: {type(exc).__name__}: {exc}",
                receipt_path=receipt,
            )
        except Exception:
            pass
        raise


def apply_phase_b1_join_key_normalization(run_sql: RunSql) -> PhaseB1ApplyResult:
    return _apply_join_key_normalization(
        run_sql,
        migration_id="20260614_phase_b1_join_key_collation_width_normalization",
        targets=TARGET_COLUMNS,
        expected_target_count=12,
        receipt_subdir="phase_b1_join_key_normalization",
        stem_prefix="phase_b1_join_key_normalization",
        preflight_collector=collect_phase_b1_join_key_preflight,
        statement_builder=build_required_alter_statements,
        notes="manual phase-b1 join-key collation/width normalization",
    )


def apply_phase_b1_session_stamp_backlog_normalization(run_sql: RunSql) -> PhaseB1ApplyResult:
    return _apply_join_key_normalization(
        run_sql,
        migration_id="20260614_phase_b1_session_stamp_backlog_normalization",
        targets=BACKLOG_SESSION_STAMP_TARGET_COLUMNS,
        expected_target_count=7,
        receipt_subdir="phase_b1_session_stamp_backlog_normalization",
        stem_prefix="phase_b1_session_stamp_backlog_normalization",
        preflight_collector=collect_phase_b1_session_stamp_backlog_preflight,
        statement_builder=build_required_backlog_session_stamp_alter_statements,
        notes="manual phase-b1 session-stamp backlog normalization",
    )


def _collect_join_key_preflight(
    run_sql: RunSql,
    *,
    targets: Sequence[Mapping[str, Any]],
    sample_limit: int,
) -> dict[str, Any]:
    columns: list[dict[str, Any]] = []
    duplicate_rows: list[dict[str, Any]] = []
    width_rows: list[dict[str, Any]] = []
    view_dependency_rows: list[dict[str, Any]] = []
    duplicate_collision_count = 0
    width_violation_count = 0
    views_requiring_recreate: set[str] = set()

    for spec in targets:
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
        duplicate_summary = _duplicate_collapse_summary(run_sql, table_name, column_name)
        collisions = _duplicate_collapse_rows(run_sql, table_name, column_name, sample_limit=sample_limit)
        duplicate_collision_count += len(collisions)
        duplicate_rows.extend(
            {
                "table": table_name,
                "column": column_name,
                "normalized_value": row.get("normalized_value"),
                "row_count": int(row.get("row_count") or 0),
                "raw_distinct_count": int(row.get("raw_distinct_count") or 0),
                "raw_values": row.get("raw_values"),
            }
            for row in collisions
        )
        max_observed_length = stats.get("max_observed_length")
        target_width = int(spec["target_width"])
        width_violation = bool(max_observed_length is not None and int(max_observed_length) > target_width)
        if width_violation:
            width_violation_count += 1
        width_rows.append(
            {
                "table": table_name,
                "column": column_name,
                "max_observed_length": int(max_observed_length or 0),
                "target_width": target_width,
                "width_safe": "yes" if not width_violation else "no",
            }
        )

        column_row = {
            "table": table_name,
            "column": column_name,
            "current_type": current.get("column_type"),
            "current_charset": current.get("character_set_name"),
            "current_collation": current.get("collation_name"),
            "current_width": current.get("character_maximum_length"),
            "target_type": f"{spec['target_type']}({spec['target_width']})",
            "target_charset": spec["target_charset"],
            "target_collation": spec["target_collation"],
            "target_width": spec["target_width"],
            "nullable": current.get("is_nullable"),
            "indexed": "yes" if indexes else "no",
            "index_names": ", ".join(str(row.get("index_name") or "") for row in indexes if str(row.get("index_name") or "")),
            "foreign_key_involved": "yes" if _fk_involved(run_sql, table_name, column_name) else "no",
            "view_dependencies": ", ".join(views),
            "writer_dependencies": spec["writer_dependencies"],
            "row_count": int(stats.get("row_count") or 0),
            "null_count": int(stats.get("null_count") or 0),
            "distinct_count": int(stats.get("distinct_count") or 0),
            "max_observed_length": int(max_observed_length or 0),
            "raw_distinct_count": int(duplicate_summary.get("raw_distinct_count") or 0),
            "normalized_distinct_count": int(duplicate_summary.get("normalized_distinct_count") or 0),
            "duplicate_collapse_risk": int(duplicate_summary.get("raw_distinct_count") or 0)
            - int(duplicate_summary.get("normalized_distinct_count") or 0),
            "width_violation": "yes" if width_violation else "no",
            "notes": spec.get("notes") or "",
        }
        columns.append(column_row)

    join_parity_before = _join_parity_rows(run_sql)
    preview = migration_preview("20260614_phase_b1_join_key_collation_width_normalization")
    required_statements = build_required_alter_statements(run_sql)
    planned_sql_for_report = (
        required_alter_sql(run_sql)
        if duplicate_collision_count == 0 and width_violation_count == 0
        else ""
    )
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "target_column_count": len(targets),
        "duplicate_collision_count": duplicate_collision_count,
        "width_violation_count": width_violation_count,
        "all_target_columns_match_spec": len(columns) == len(targets),
        "duplicate_collapse_risk_zero": duplicate_collision_count == 0 and all(
            int(row.get("duplicate_collapse_risk") or 0) == 0 for row in columns
        ),
        "width_safety_ok": width_violation_count == 0,
        "views_requiring_recreate_count": len(views_requiring_recreate),
        "join_parity_count": len(join_parity_before),
        "required_alter_statement_count": len(required_statements),
        "planned_alter_generated": bool(planned_sql_for_report),
        "preflight_clean": duplicate_collision_count == 0 and width_violation_count == 0 and len(columns) == len(targets),
    }
    return {
        "summary": summary,
        "columns": columns,
        "duplicate_checks": duplicate_rows,
        "width_checks": width_rows,
        "join_parity_before": join_parity_before,
        "view_dependencies": view_dependency_rows,
        "views_requiring_recreate": sorted(views_requiring_recreate),
        "planned_alter_sql": planned_sql_for_report,
        "migration_registry_preview": preview,
    }


def collect_phase_b1_join_key_preflight(run_sql: RunSql, *, sample_limit: int = 20) -> dict[str, Any]:
    return _collect_join_key_preflight(
        run_sql,
        targets=TARGET_COLUMNS,
        sample_limit=sample_limit,
    )


def collect_phase_b1_session_stamp_backlog_preflight(run_sql: RunSql, *, sample_limit: int = 20) -> dict[str, Any]:
    return _collect_join_key_preflight(
        run_sql,
        targets=BACKLOG_SESSION_STAMP_TARGET_COLUMNS,
        sample_limit=sample_limit,
    )


def write_phase_b1_join_key_preflight_bundle(report: Mapping[str, Any], output_dir: Path, *, stem: str) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}

    json_path = output_dir / f"{stem}_preflight.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    files["json"] = str(json_path.resolve())

    csv_payloads = {
        f"{stem}_columns.csv": report.get("columns") or [],
        f"{stem}_duplicate_checks.csv": report.get("duplicate_checks") or [],
        f"{stem}_width_checks.csv": report.get("width_checks") or [],
        f"{stem}_join_parity_before.csv": report.get("join_parity_before") or [],
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


def write_phase_b1_session_stamp_backlog_preflight_bundle(
    report: Mapping[str, Any],
    output_dir: Path,
    *,
    stem: str,
) -> dict[str, str]:
    return write_phase_b1_join_key_preflight_bundle(report, output_dir, stem=stem)


__all__ = [
    "BACKLOG_SESSION_STAMP_TARGET_COLUMNS",
    "TARGET_COLUMNS",
    "TARGET_COLLATION",
    "TARGET_CHARSET",
    "TARGET_SESSION_STAMP_WIDTH",
    "PhaseB1ApplyResult",
    "apply_phase_b1_join_key_normalization",
    "apply_phase_b1_session_stamp_backlog_normalization",
    "backlog_session_stamp_target_columns",
    "build_required_alter_statements",
    "build_required_backlog_session_stamp_alter_statements",
    "collect_phase_b1_join_key_preflight",
    "collect_phase_b1_session_stamp_backlog_preflight",
    "migration_preview",
    "planned_alter_sql",
    "planned_backlog_session_stamp_alter_sql",
    "required_alter_sql",
    "target_columns",
    "write_phase_b1_apply_receipt",
    "write_phase_b1_join_key_preflight_bundle",
    "write_phase_b1_session_stamp_backlog_preflight_bundle",
]
