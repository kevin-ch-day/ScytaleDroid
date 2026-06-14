"""Read-only parity audit for Phase A typed replacement read paths."""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_queries.sql_typed_reads import (
    resolved_dynamic_session_static_run_id,
    resolved_static_run_started_at_utc,
)
from scytaledroid.Database.db_utils.schema_migration_registry import latest_schema_version

RunSql = Callable[..., Any]


def _rows(run_sql: RunSql, sql: str, params: Sequence[Any] | None = None, *, query_name: str) -> list[dict[str, Any]]:
    out = run_sql(sql, tuple(params or ()), fetch="all", dictionary=True, query_name=query_name) or []
    return [dict(row) for row in out if isinstance(row, Mapping)]


def _row(run_sql: RunSql, sql: str, params: Sequence[Any] | None = None, *, query_name: str) -> dict[str, Any]:
    out = run_sql(sql, tuple(params or ()), fetch="one", dictionary=True, query_name=query_name) or {}
    return dict(out) if isinstance(out, Mapping) else {}


def collect_phase_a_read_parity(run_sql: RunSql, *, sample_limit: int = 20) -> dict[str, Any]:
    resolved_static_run_id = resolved_dynamic_session_static_run_id("ds")
    resolved_started_at = resolved_static_run_started_at_utc("sar")

    dynamic_summary = _row(
        run_sql,
        f"""
        SELECT
          COUNT(*) AS dynamic_sessions_total,
          SUM(CASE WHEN ds.static_run_id IS NOT NULL THEN 1 ELSE 0 END) AS legacy_static_run_id_present_rows,
          SUM(CASE WHEN ds.static_run_id_u IS NOT NULL THEN 1 ELSE 0 END) AS typed_static_run_id_present_rows,
          SUM(CASE WHEN {resolved_static_run_id} IS NOT NULL THEN 1 ELSE 0 END) AS resolved_static_run_id_present_rows,
          SUM(CASE
                WHEN ds.static_run_id IS NOT NULL
                 AND EXISTS (
                   SELECT 1 FROM static_analysis_runs sar_legacy
                   WHERE sar_legacy.id = CAST(ds.static_run_id AS UNSIGNED)
                 )
                THEN 1 ELSE 0
              END) AS legacy_static_run_linked_rows,
          SUM(CASE
                WHEN {resolved_static_run_id} IS NOT NULL
                 AND EXISTS (
                   SELECT 1 FROM static_analysis_runs sar_typed
                   WHERE sar_typed.id = {resolved_static_run_id}
                 )
                THEN 1 ELSE 0
              END) AS typed_static_run_linked_rows,
          SUM(CASE
                WHEN
                  (
                    CASE
                      WHEN ds.static_run_id IS NOT NULL
                       AND EXISTS (
                         SELECT 1 FROM static_analysis_runs sar_legacy
                         WHERE sar_legacy.id = CAST(ds.static_run_id AS UNSIGNED)
                       )
                      THEN 1 ELSE 0
                    END
                  ) <>
                  (
                    CASE
                      WHEN {resolved_static_run_id} IS NOT NULL
                       AND EXISTS (
                         SELECT 1 FROM static_analysis_runs sar_typed
                         WHERE sar_typed.id = {resolved_static_run_id}
                       )
                      THEN 1 ELSE 0
                    END
                  )
                THEN 1 ELSE 0
              END) AS static_link_state_mismatch_rows
        FROM dynamic_sessions ds
        """,
        query_name="phase_a_read_parity.dynamic_summary",
    )
    dynamic_mismatch_samples = _rows(
        run_sql,
        f"""
        SELECT
          ds.dynamic_run_id,
          ds.package_name,
          ds.static_run_id,
          ds.static_run_id_u,
          {resolved_static_run_id} AS resolved_static_run_id
        FROM dynamic_sessions ds
        WHERE
          (
            CASE
              WHEN ds.static_run_id IS NOT NULL
               AND EXISTS (
                 SELECT 1 FROM static_analysis_runs sar_legacy
                 WHERE sar_legacy.id = CAST(ds.static_run_id AS UNSIGNED)
               )
              THEN 1 ELSE 0
            END
          ) <>
          (
            CASE
              WHEN {resolved_static_run_id} IS NOT NULL
               AND EXISTS (
                 SELECT 1 FROM static_analysis_runs sar_typed
                 WHERE sar_typed.id = {resolved_static_run_id}
               )
              THEN 1 ELSE 0
            END
          )
        ORDER BY ds.started_at_utc DESC, ds.dynamic_run_id DESC
        LIMIT %s
        """,
        (int(sample_limit),),
        query_name="phase_a_read_parity.dynamic_mismatch_samples",
    )

    static_summary = _row(
        run_sql,
        f"""
        SELECT
          COUNT(*) AS static_runs_total,
          SUM(CASE
                WHEN
                  COALESCE(
                    STR_TO_DATE(REPLACE(REPLACE(sar.run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f'),
                    STR_TO_DATE(REPLACE(REPLACE(sar.run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')
                  ) IS NOT NULL
                THEN 1 ELSE 0
              END) AS legacy_parseable_started_rows,
          SUM(CASE WHEN sar.run_started_at_utc IS NOT NULL THEN 1 ELSE 0 END) AS typed_started_rows,
          SUM(CASE WHEN {resolved_started_at} IS NOT NULL THEN 1 ELSE 0 END) AS resolved_started_rows,
          SUM(CASE
                WHEN
                  (
                    CASE
                      WHEN
                        COALESCE(
                          STR_TO_DATE(REPLACE(REPLACE(sar.run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f'),
                          STR_TO_DATE(REPLACE(REPLACE(sar.run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')
                        ) IS NOT NULL
                      THEN 1 ELSE 0
                    END
                  ) <>
                  (
                    CASE WHEN sar.run_started_at_utc IS NOT NULL THEN 1 ELSE 0 END
                  )
                THEN 1 ELSE 0
              END) AS started_at_parity_mismatch_rows
        FROM static_analysis_runs sar
        """,
        query_name="phase_a_read_parity.static_summary",
    )
    static_mismatch_samples = _rows(
        run_sql,
        """
        SELECT
          sar.id,
          sar.session_stamp,
          sar.run_started_utc,
          sar.run_started_at_utc
        FROM static_analysis_runs sar
        WHERE
          (
            CASE
              WHEN
                COALESCE(
                  STR_TO_DATE(REPLACE(REPLACE(sar.run_started_utc,'T',' '),'Z',''), '%%Y-%%m-%%d %%H:%%i:%%s.%%f'),
                  STR_TO_DATE(REPLACE(REPLACE(sar.run_started_utc,'T',' '),'Z',''), '%%Y-%%m-%%d %%H:%%i:%%s')
                ) IS NOT NULL
              THEN 1 ELSE 0
            END
          ) <>
          (
            CASE WHEN sar.run_started_at_utc IS NOT NULL THEN 1 ELSE 0 END
          )
        ORDER BY sar.id DESC
        LIMIT %s
        """,
        (int(sample_limit),),
        query_name="phase_a_read_parity.static_mismatch_samples",
    )

    artifact_summary = _row(
        run_sql,
        """
        SELECT
          COUNT(*) AS dynamic_artifact_rows,
          SUM(CASE
                WHEN dynamic_run_id IS NOT NULL
                 AND TRIM(dynamic_run_id) <> ''
                 AND CHAR_LENGTH(dynamic_run_id) = 36
                 AND dynamic_run_id REGEXP '^[0-9a-fA-F-]{36}$'
                THEN 1 ELSE 0
              END) AS uuid_like_dynamic_run_id_rows,
          SUM(CASE WHEN dynamic_run_uuid IS NOT NULL THEN 1 ELSE 0 END) AS typed_dynamic_run_uuid_rows,
          SUM(CASE
                WHEN dynamic_run_id IS NOT NULL
                 AND TRIM(dynamic_run_id) <> ''
                 AND CHAR_LENGTH(dynamic_run_id) = 36
                 AND dynamic_run_id REGEXP '^[0-9a-fA-F-]{36}$'
                 AND COALESCE(dynamic_run_uuid, '') <> LOWER(TRIM(dynamic_run_id))
                THEN 1 ELSE 0
              END) AS dynamic_run_uuid_parity_mismatch_rows
        FROM artifact_registry
        WHERE run_type = 'dynamic'
        """,
        query_name="phase_a_read_parity.artifact_summary",
    )
    artifact_mismatch_samples = _rows(
        run_sql,
        """
        SELECT
          artifact_id,
          run_id,
          dynamic_run_id,
          dynamic_run_uuid,
          linkage_migration_status
        FROM artifact_registry
        WHERE run_type = 'dynamic'
          AND dynamic_run_id IS NOT NULL
          AND TRIM(dynamic_run_id) <> ''
          AND CHAR_LENGTH(dynamic_run_id) = 36
          AND dynamic_run_id REGEXP '^[0-9a-fA-F-]{36}$'
          AND COALESCE(dynamic_run_uuid, '') <> LOWER(TRIM(dynamic_run_id))
        ORDER BY artifact_id DESC
        LIMIT %s
        """,
        (int(sample_limit),),
        query_name="phase_a_read_parity.artifact_mismatch_samples",
    )

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "live_schema_version": latest_schema_version(run_sql),
        **{key: int(value or 0) for key, value in dynamic_summary.items()},
        **{key: int(value or 0) for key, value in static_summary.items()},
        **{key: int(value or 0) for key, value in artifact_summary.items()},
        "parity_clean": bool(
            int(dynamic_summary.get("static_link_state_mismatch_rows") or 0) == 0
            and int(static_summary.get("started_at_parity_mismatch_rows") or 0) == 0
            and int(artifact_summary.get("dynamic_run_uuid_parity_mismatch_rows") or 0) == 0
        ),
    }
    return {
        "summary": summary,
        "dynamic_link_mismatch_samples": dynamic_mismatch_samples,
        "static_started_at_mismatch_samples": static_mismatch_samples,
        "artifact_dynamic_uuid_mismatch_samples": artifact_mismatch_samples,
    }


def write_phase_a_read_parity_bundle(report: Mapping[str, Any], output_dir: Path, *, stem: str) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}
    json_path = output_dir / f"{stem}.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    files["json"] = str(json_path.resolve())

    sections = {
        f"{stem}_dynamic_link_mismatch_samples.csv": report.get("dynamic_link_mismatch_samples") or [],
        f"{stem}_static_started_at_mismatch_samples.csv": report.get("static_started_at_mismatch_samples") or [],
        f"{stem}_artifact_dynamic_uuid_mismatch_samples.csv": report.get("artifact_dynamic_uuid_mismatch_samples") or [],
    }
    for filename, rows in sections.items():
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
    return files


__all__ = [
    "collect_phase_a_read_parity",
    "write_phase_a_read_parity_bundle",
]
