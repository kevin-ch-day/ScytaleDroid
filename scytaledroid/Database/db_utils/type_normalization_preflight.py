"""Read-only preflight audit for Phase A type normalization."""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RunSql = Callable[..., Any]


def _rows(run_sql: RunSql, sql: str, params: Sequence[Any] | None = None, *, query_name: str) -> list[dict[str, Any]]:
    out = run_sql(sql, tuple(params or ()), fetch="all", dictionary=True, query_name=query_name) or []
    return [dict(row) for row in out if isinstance(row, Mapping)]


def _row(run_sql: RunSql, sql: str, params: Sequence[Any] | None = None, *, query_name: str) -> dict[str, Any]:
    out = run_sql(sql, tuple(params or ()), fetch="one", dictionary=True, query_name=query_name) or {}
    return dict(out) if isinstance(out, Mapping) else {}


def collect_type_normalization_preflight(run_sql: RunSql) -> dict[str, Any]:
    dynamic_uuid = _row(
        run_sql,
        """
        SELECT
          COUNT(*) AS total_dynamic_registry_rows,
          SUM(CASE WHEN dynamic_run_id IS NULL OR TRIM(dynamic_run_id) = '' THEN 1 ELSE 0 END) AS blank_dynamic_run_id_rows,
          SUM(CASE WHEN CHAR_LENGTH(dynamic_run_id) = 36 THEN 1 ELSE 0 END) AS dynamic_run_id_len36_rows,
          SUM(CASE WHEN dynamic_run_id REGEXP '^[0-9a-fA-F-]{36}$' THEN 1 ELSE 0 END) AS uuid_like_dynamic_run_id_rows,
          SUM(CASE WHEN dynamic_run_id IS NOT NULL AND TRIM(dynamic_run_id) <> '' AND CHAR_LENGTH(dynamic_run_id) <> 36 THEN 1 ELSE 0 END) AS incompatible_dynamic_run_id_length_rows
        FROM artifact_registry
        WHERE run_type = 'dynamic'
        """,
        query_name="type_preflight.dynamic_uuid",
    )
    dynamic_uuid["malformed_dynamic_uuid_rows"] = int(dynamic_uuid.get("total_dynamic_registry_rows") or 0) - int(
        dynamic_uuid.get("blank_dynamic_run_id_rows") or 0
    ) - int(dynamic_uuid.get("uuid_like_dynamic_run_id_rows") or 0)

    static_fk = _row(
        run_sql,
        """
        SELECT
          COUNT(*) AS dynamic_sessions_static_run_id_nonnull_rows,
          SUM(CASE WHEN sar.id IS NULL THEN 1 ELSE 0 END) AS dynamic_sessions_static_run_id_orphan_rows
        FROM dynamic_sessions ds
        LEFT JOIN static_analysis_runs sar
          ON sar.id = CAST(ds.static_run_id AS UNSIGNED)
        WHERE ds.static_run_id IS NOT NULL
        """,
        query_name="type_preflight.dynamic_static_fk",
    )
    signedness = {
        "dynamic_sessions_static_run_id_type": _rows(
            run_sql,
            """
            SELECT column_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'dynamic_sessions'
              AND column_name = 'static_run_id'
            """,
            query_name="type_preflight.dynamic_static_type",
        ),
        "static_analysis_runs_id_type": _rows(
            run_sql,
            """
            SELECT column_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'static_analysis_runs'
              AND column_name = 'id'
            """,
            query_name="type_preflight.static_run_pk_type",
        ),
    }

    run_started = _row(
        run_sql,
        """
        SELECT
          COUNT(*) AS total_static_runs,
          SUM(CASE WHEN run_started_utc IS NULL OR TRIM(run_started_utc) = '' THEN 1 ELSE 0 END) AS blank_run_started_rows,
          SUM(CASE WHEN
              STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f') IS NOT NULL
              OR STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s') IS NOT NULL
            THEN 1 ELSE 0 END) AS parseable_run_started_rows,
          SUM(CASE WHEN
              run_started_utc IS NOT NULL AND TRIM(run_started_utc) <> ''
              AND STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f') IS NULL
              AND STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s') IS NULL
            THEN 1 ELSE 0 END) AS unparseable_run_started_rows
        FROM static_analysis_runs
        """,
        query_name="type_preflight.run_started",
    )

    status_domains = _rows(
        run_sql,
        """
        SELECT 'artifact_registry.run_type' AS domain_name, run_type AS domain_value, COUNT(*) AS row_count
        FROM artifact_registry GROUP BY run_type
        UNION ALL
        SELECT 'artifact_registry.linkage_migration_status', linkage_migration_status, COUNT(*)
        FROM artifact_registry GROUP BY linkage_migration_status
        UNION ALL
        SELECT 'dynamic_sessions.status', COALESCE(status, '<NULL>'), COUNT(*)
        FROM dynamic_sessions GROUP BY status
        UNION ALL
        SELECT 'static_analysis_runs.status', COALESCE(status, '<NULL>'), COUNT(*)
        FROM static_analysis_runs GROUP BY status
        UNION ALL
        SELECT 'static_analysis_sessions.session_status', session_status, COUNT(*)
        FROM static_analysis_sessions GROUP BY session_status
        UNION ALL
        SELECT 'static_analysis_sessions.session_disposition', session_disposition, COUNT(*)
        FROM static_analysis_sessions GROUP BY session_disposition
        ORDER BY domain_name, row_count DESC, domain_value
        """,
        query_name="type_preflight.status_domains",
    )

    collation_rows = _rows(
        run_sql,
        """
        SELECT table_name, column_name, collation_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND column_name IN ('package_name','session_stamp','profile_key','scenario_id','dynamic_run_id','run_id')
          AND collation_name IS NOT NULL
        ORDER BY column_name, table_name
        """,
        query_name="type_preflight.collation_rows",
    )
    collation_groups: dict[str, set[str]] = {}
    for row in collation_rows:
        key = str(row.get("column_name") or "")
        collation_groups.setdefault(key, set()).add(str(row.get("collation_name") or ""))
    collation_drift = [
        {
            "column_name": key,
            "distinct_collations": ",".join(sorted(values)),
            "distinct_collation_count": len(values),
        }
        for key, values in sorted(collation_groups.items())
        if len(values) > 1
    ]

    fk_candidates = [
        {
            "candidate_fk": "dynamic_sessions.static_run_id -> static_analysis_runs.id",
            "nonnull_source_rows": int(static_fk.get("dynamic_sessions_static_run_id_nonnull_rows") or 0),
            "orphan_source_rows": int(static_fk.get("dynamic_sessions_static_run_id_orphan_rows") or 0),
            "signedness_mismatch_risk": 1,
        },
        {
            "candidate_fk": "artifact_registry.dynamic_run_uuid -> dynamic_sessions.dynamic_run_id",
            "nonnull_source_rows": int(dynamic_uuid.get("uuid_like_dynamic_run_id_rows") or 0),
            "orphan_source_rows": 0,
            "signedness_mismatch_risk": 0,
        },
    ]

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "dynamic_uuid_compatibility": dynamic_uuid,
        "dynamic_sessions_static_run_fk_preflight": static_fk,
        "signedness_metadata": signedness,
        "run_started_utc_preflight": run_started,
        "collation_drift_count": len(collation_drift),
        "fk_candidate_count": len(fk_candidates),
        "status_domain_count": len(status_domains),
        "preflight_clean": bool(
            int(dynamic_uuid.get("blank_dynamic_run_id_rows") or 0) == 0
            and int(dynamic_uuid.get("malformed_dynamic_uuid_rows") or 0) == 0
            and int(static_fk.get("dynamic_sessions_static_run_id_orphan_rows") or 0) == 0
            and int(run_started.get("unparseable_run_started_rows") or 0) == 0
        ),
    }
    return {
        "summary": summary,
        "status_domains": status_domains,
        "collation_drift": collation_drift,
        "fk_candidates": fk_candidates,
        "raw_collation_rows": collation_rows,
    }


def write_type_normalization_preflight_bundle(report: Mapping[str, Any], output_dir: Path, *, stem: str) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    base = str(stem)
    json_path = output_dir / f"{base}.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

    files = {"json": str(json_path.resolve())}
    csv_payloads = {
        f"{base}_status_domains.csv": report.get("status_domains") or [],
        f"{base}_collation_drift.csv": report.get("collation_drift") or [],
        f"{base}_fk_candidates.csv": report.get("fk_candidates") or [],
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
    return files


__all__ = [
    "collect_type_normalization_preflight",
    "write_type_normalization_preflight_bundle",
]
