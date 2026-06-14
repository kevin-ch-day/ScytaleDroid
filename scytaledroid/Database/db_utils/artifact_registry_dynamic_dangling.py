"""Read-only dynamic dangling registry audit helpers.

Correlates ``artifact_registry`` rows that are dangling against the live dynamic
schema and the local filesystem. This module does not perform any DML/DDL.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

RunSql = Callable[..., Any]

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

OUTPUT_FILES: tuple[str, ...] = (
    "summary.json",
    "dynamic_schema_inventory.csv",
    "dynamic_dangling_rows.csv",
    "dynamic_dangling_runs.csv",
    "dynamic_dangling_reason_counts.csv",
    "dynamic_dangling_reason_samples.csv",
)

SCHEMA_TABLE_ORDER: tuple[str, ...] = (
    "dynamic_sessions",
    "dynamic_network_features",
    "dynamic_network_indicators",
    "dynamic_session_issues",
    "dynamic_telemetry_network",
    "dynamic_telemetry_process",
    "analysis_cohort_runs",
    "analysis_dynamic_cohort_status",
    "ml_feature_windows",
    "ml_scores",
)

DB_REFERENCE_FIELDS: tuple[str, ...] = (
    "has_analysis_cohort_run",
    "has_analysis_dynamic_status",
    "has_dynamic_network_features",
    "has_dynamic_network_indicators",
    "has_dynamic_session_issues",
    "has_dynamic_telemetry_network",
    "has_dynamic_telemetry_process",
    "has_ml_feature_windows",
    "has_ml_scores",
)

REASON_FIELDS: tuple[str, ...] = (
    "missing_dynamic_session",
    "missing_evidence_file",
    "evidence_file_exists_but_db_detached",
    "db_reference_exists_but_file_missing",
    "malformed_dynamic_run_id",
    "unknown_needs_review",
)


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


def _norm_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, "", 0, "0", "false", "False", "FALSE"):
        return False
    return bool(value)


def _rows(run_sql: RunSql, sql: str, params: Sequence[Any] | None = None, *, query_name: str) -> list[dict[str, Any]]:
    out = run_sql(sql, tuple(params or ()), fetch="all", dictionary=True, query_name=query_name) or []
    return [dict(row) for row in out if isinstance(row, Mapping)]


def _row(run_sql: RunSql, sql: str, params: Sequence[Any] | None = None, *, query_name: str) -> dict[str, Any]:
    out = run_sql(sql, tuple(params or ()), fetch="one", dictionary=True, query_name=query_name) or {}
    return dict(out) if isinstance(out, Mapping) else {}


def _age_bucket(value: Any, *, now: datetime | None = None) -> str:
    text = _norm_text_or_none(value)
    if not text:
        return "null_created_at"
    dt: datetime | None = None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(text, fmt)
            break
        except ValueError:
            continue
    if dt is None:
        return "unknown_created_at"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    ref = now or datetime.now(UTC)
    age_days = max(0.0, (ref - dt.astimezone(UTC)).total_seconds() / 86400.0)
    if age_days < 7:
        return "0-7d"
    if age_days < 90:
        return "7-90d"
    return "90d+"


def _path_exists(host_path: str | None) -> bool | None:
    hp = _norm_text_or_none(host_path)
    if not hp:
        return None
    try:
        return Path(hp).is_file()
    except OSError:
        return False


def _uuid_like(value: str | None) -> bool:
    text = _norm_text_or_none(value)
    return bool(text and UUID_RE.match(text))


def _workspace_prefix(host_path: str | None) -> str | None:
    hp = _norm_text_or_none(host_path)
    if not hp:
        return None
    marker = "/output/"
    if marker in hp:
        return hp.split(marker, 1)[0]
    return str(Path(hp).parent)


def _schema_inventory(run_sql: RunSql) -> tuple[list[dict[str, Any]], set[str]]:
    rows = _rows(
        run_sql,
        """
        SELECT table_name, column_name, column_type
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND (
            table_name LIKE 'dynamic\\_%'
            OR table_name IN ('analysis_cohort_runs', 'analysis_dynamic_cohort_status', 'ml_feature_windows', 'ml_scores')
          )
        ORDER BY table_name, ordinal_position
        """,
        query_name="artifact_registry_dynamic_dangling.schema_inventory",
    )
    by_table: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_table[_norm_text(row.get("table_name"))].append(row)

    schema_rows: list[dict[str, Any]] = []
    discovered_tables: set[str] = set()
    for table_name in SCHEMA_TABLE_ORDER:
        columns = by_table.get(table_name)
        if not columns:
            continue
        discovered_tables.add(table_name)
        column_names = [_norm_text(col.get("column_name")) for col in columns]
        schema_rows.append(
            {
                "table_name": table_name,
                "column_count": len(columns),
                "columns_csv": ",".join(column_names),
                "dynamic_run_id_present": "dynamic_run_id" in column_names,
                "run_id_present": "run_id" in column_names,
                "static_run_id_present": "static_run_id" in column_names,
                "evidence_path_present": "evidence_path" in column_names,
                "pcap_relpath_present": "pcap_relpath" in column_names,
                "base_apk_sha256_present": "base_apk_sha256" in column_names,
                "static_handoff_hash_present": "static_handoff_hash" in column_names,
                "created_at_present": any(name in {"created_at", "created_at_utc"} for name in column_names),
            }
        )
    return schema_rows, discovered_tables


def _collect_totals(run_sql: RunSql) -> dict[str, int]:
    row = _row(
        run_sql,
        """
        SELECT
          SUM(CASE WHEN run_type = 'dynamic' AND link_state = 'linked' THEN 1 ELSE 0 END) AS linked_dynamic_registry_rows,
          SUM(CASE WHEN run_type = 'dynamic' AND link_state = 'dangling_dynamic_run' THEN 1 ELSE 0 END) AS dangling_dynamic_registry_rows
        FROM v_artifact_registry_integrity
        """,
        query_name="artifact_registry_dynamic_dangling.dynamic_totals",
    )
    return {
        "linked_dynamic_registry_rows": int(row.get("linked_dynamic_registry_rows") or 0),
        "dangling_dynamic_registry_rows": int(row.get("dangling_dynamic_registry_rows") or 0),
    }


def _dangling_row_sql(discovered_tables: set[str]) -> str:
    def _exists(alias: str, table_name: str, join_expr: str) -> str:
        if table_name not in discovered_tables:
            return f"0 AS {alias}"
        return f"EXISTS(SELECT 1 FROM {table_name} t WHERE {join_expr}) AS {alias}"

    select_bits = [
        "v.artifact_id",
        "v.run_type",
        "v.run_id",
        "v.dynamic_run_id",
        "v.resolved_dynamic_run_id",
        "v.link_state",
        "v.linkage_resolution_path",
        "v.artifact_type",
        "v.host_path",
        "v.created_at_utc",
        "v.status_reason",
        "JSON_UNQUOTE(JSON_EXTRACT(v.meta_json, '$.package_name')) AS meta_package_name",
        "JSON_UNQUOTE(JSON_EXTRACT(v.meta_json, '$.static_run_id')) AS meta_static_run_id",
        "JSON_UNQUOTE(JSON_EXTRACT(v.meta_json, '$.static_handoff_hash')) AS meta_static_handoff_hash",
        "JSON_UNQUOTE(JSON_EXTRACT(v.meta_json, '$.base_apk_sha256')) AS meta_base_apk_sha256",
        _exists("has_dynamic_session", "dynamic_sessions", "t.dynamic_run_id = v.resolved_dynamic_run_id"),
        _exists("has_analysis_cohort_run", "analysis_cohort_runs", "t.dynamic_run_id = v.resolved_dynamic_run_id"),
        _exists("has_analysis_dynamic_status", "analysis_dynamic_cohort_status", "t.dynamic_run_id = v.resolved_dynamic_run_id"),
        _exists("has_dynamic_network_features", "dynamic_network_features", "t.dynamic_run_id = v.resolved_dynamic_run_id"),
        _exists("has_dynamic_network_indicators", "dynamic_network_indicators", "t.dynamic_run_id = v.resolved_dynamic_run_id"),
        _exists("has_dynamic_session_issues", "dynamic_session_issues", "t.dynamic_run_id = v.resolved_dynamic_run_id"),
        _exists("has_dynamic_telemetry_network", "dynamic_telemetry_network", "t.dynamic_run_id = v.resolved_dynamic_run_id"),
        _exists("has_dynamic_telemetry_process", "dynamic_telemetry_process", "t.dynamic_run_id = v.resolved_dynamic_run_id"),
        _exists(
            "has_ml_feature_windows",
            "ml_feature_windows",
            "t.run_type = 'dynamic' AND t.run_id = v.resolved_dynamic_run_id",
        ),
        _exists(
            "has_ml_scores",
            "ml_scores",
            "t.run_type = 'dynamic' AND t.run_id = v.resolved_dynamic_run_id",
        ),
    ]
    return f"""
        SELECT
          {", ".join(select_bits)}
        FROM v_artifact_registry_integrity v
        WHERE v.run_type = 'dynamic'
          AND v.link_state = 'dangling_dynamic_run'
        ORDER BY v.created_at_utc, v.artifact_id
    """


def _classify_row(row: Mapping[str, Any], *, repo_root: Path) -> dict[str, Any]:
    resolved_dynamic_run_id = _norm_text_or_none(row.get("resolved_dynamic_run_id") or row.get("dynamic_run_id") or row.get("run_id"))
    host_path = _norm_text_or_none(row.get("host_path"))
    file_exists = _path_exists(host_path)
    malformed = not _uuid_like(resolved_dynamic_run_id)
    other_db_refs = any(_norm_bool(row.get(field)) for field in DB_REFERENCE_FIELDS)
    has_dynamic_session = _norm_bool(row.get("has_dynamic_session"))
    has_static_reference = any(
        _norm_text_or_none(row.get(field))
        for field in ("meta_static_run_id", "meta_static_handoff_hash", "meta_base_apk_sha256")
    )
    if malformed:
        primary_reason = "malformed_dynamic_run_id"
    elif has_dynamic_session:
        primary_reason = "unknown_needs_review"
    elif other_db_refs or file_exists:
        primary_reason = "partially_linked"
    elif file_exists is False:
        primary_reason = "truly_detached"
    else:
        primary_reason = "unknown_needs_review"

    reason_flags: dict[str, bool] = {
        "missing_dynamic_session": not has_dynamic_session,
        "missing_evidence_file": file_exists is False,
        "evidence_file_exists_but_db_detached": (file_exists is True) and not has_dynamic_session and not other_db_refs,
        "db_reference_exists_but_file_missing": other_db_refs and (file_exists is False),
        "malformed_dynamic_run_id": malformed,
        "unknown_needs_review": primary_reason == "unknown_needs_review",
    }
    db_reference_names = [field for field in DB_REFERENCE_FIELDS if _norm_bool(row.get(field))]
    repo_root_text = str(repo_root.resolve())
    under_repo_root = bool(host_path and host_path.startswith(repo_root_text))
    return {
        "artifact_id": int(row.get("artifact_id") or 0),
        "run_type": _norm_text_or_none(row.get("run_type")),
        "run_id": _norm_text_or_none(row.get("run_id")),
        "dynamic_run_id": _norm_text_or_none(row.get("dynamic_run_id")),
        "resolved_dynamic_run_id": resolved_dynamic_run_id,
        "artifact_type": _norm_text_or_none(row.get("artifact_type")),
        "host_path": host_path,
        "host_workspace_prefix": _workspace_prefix(host_path),
        "host_path_exists": file_exists,
        "host_path_under_repo_root": under_repo_root,
        "created_at_utc": _norm_text_or_none(row.get("created_at_utc")),
        "age_bucket": _age_bucket(row.get("created_at_utc")),
        "status_reason": _norm_text_or_none(row.get("status_reason")),
        "link_state": _norm_text_or_none(row.get("link_state")),
        "linkage_resolution_path": _norm_text_or_none(row.get("linkage_resolution_path")),
        "meta_package_name": _norm_text_or_none(row.get("meta_package_name")),
        "meta_static_run_id": _norm_text_or_none(row.get("meta_static_run_id")),
        "meta_static_handoff_hash": _norm_text_or_none(row.get("meta_static_handoff_hash")),
        "meta_base_apk_sha256": _norm_text_or_none(row.get("meta_base_apk_sha256")),
        "has_dynamic_session": has_dynamic_session,
        "has_any_dynamic_db_reference": other_db_refs,
        "db_reference_names_csv": ",".join(db_reference_names),
        "has_related_static_reference": has_static_reference,
        "primary_reason": primary_reason,
        **reason_flags,
        **{field: _norm_bool(row.get(field)) for field in DB_REFERENCE_FIELDS},
    }


def _build_run_rows(row_records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    reason_counter_by_run: dict[str, Counter[str]] = defaultdict(Counter)
    artifact_counter_by_run: dict[str, Counter[str]] = defaultdict(Counter)
    for row in row_records:
        run_id = _norm_text_or_none(row.get("resolved_dynamic_run_id") or row.get("run_id")) or "(blank)"
        group = grouped.setdefault(
            run_id,
            {
                "resolved_dynamic_run_id": run_id,
                "row_count": 0,
                "artifact_type_count": 0,
                "artifact_types_csv": "",
                "primary_reason": row.get("primary_reason"),
                "age_bucket": row.get("age_bucket"),
                "created_at_min_utc": row.get("created_at_utc"),
                "created_at_max_utc": row.get("created_at_utc"),
                "host_path_exists_true": 0,
                "host_path_exists_false": 0,
                "db_reference_names_csv": "",
                "meta_package_name": row.get("meta_package_name"),
                "meta_static_run_id": row.get("meta_static_run_id"),
                "meta_static_handoff_hash": row.get("meta_static_handoff_hash"),
            },
        )
        group["row_count"] = int(group["row_count"]) + 1
        if row.get("host_path_exists") is True:
            group["host_path_exists_true"] = int(group["host_path_exists_true"]) + 1
        elif row.get("host_path_exists") is False:
            group["host_path_exists_false"] = int(group["host_path_exists_false"]) + 1
        created = _norm_text_or_none(row.get("created_at_utc"))
        if created:
            if not group.get("created_at_min_utc") or created < str(group.get("created_at_min_utc")):
                group["created_at_min_utc"] = created
            if not group.get("created_at_max_utc") or created > str(group.get("created_at_max_utc")):
                group["created_at_max_utc"] = created
        if row.get("db_reference_names_csv"):
            current = set(filter(None, _norm_text(group.get("db_reference_names_csv")).split(",")))
            current.update(filter(None, _norm_text(row.get("db_reference_names_csv")).split(",")))
            group["db_reference_names_csv"] = ",".join(sorted(current))
        artifact_counter_by_run[run_id][_norm_text_or_none(row.get("artifact_type")) or ""] += 1
        reason_counter_by_run[run_id][_norm_text_or_none(row.get("primary_reason")) or "unknown"] += 1
    out: list[dict[str, Any]] = []
    for run_id, group in grouped.items():
        artifact_types = artifact_counter_by_run[run_id]
        reasons = reason_counter_by_run[run_id]
        dominant_reason = max(reasons.items(), key=lambda item: (item[1], item[0]))[0] if reasons else None
        group["artifact_type_count"] = len(artifact_types)
        group["artifact_types_csv"] = ",".join(sorted(artifact_types))
        group["dominant_primary_reason"] = dominant_reason
        group["primary_reason_distribution"] = json.dumps(dict(sorted(reasons.items())), sort_keys=True)
        out.append(group)
    out.sort(key=lambda row: (str(row.get("created_at_min_utc") or ""), str(row.get("resolved_dynamic_run_id") or "")))
    return out


def _build_reason_counts(
    row_records: Sequence[Mapping[str, Any]],
    *,
    linked_dynamic_registry_rows: int,
    dangling_dynamic_registry_rows: int,
) -> list[dict[str, Any]]:
    primary_counts = Counter(_norm_text_or_none(row.get("primary_reason")) or "unknown" for row in row_records)
    flag_counts = Counter()
    for row in row_records:
        for field in REASON_FIELDS:
            if _norm_bool(row.get(field)):
                flag_counts[field] += 1
    counts: list[dict[str, Any]] = [
        {"reason_bucket": "linked_dynamic_registry_rows", "count": int(linked_dynamic_registry_rows), "reason_kind": "baseline"},
        {"reason_bucket": "dangling_dynamic_registry_rows", "count": int(dangling_dynamic_registry_rows), "reason_kind": "baseline"},
    ]
    for field in REASON_FIELDS:
        counts.append({"reason_bucket": field, "count": int(flag_counts.get(field, 0)), "reason_kind": "flag"})
    for field in ("truly_detached", "partially_linked", "malformed_dynamic_run_id", "unknown_needs_review"):
        counts.append({"reason_bucket": field, "count": int(primary_counts.get(field, 0)), "reason_kind": "primary"})
    return counts


def _build_reason_samples(row_records: Sequence[Mapping[str, Any]], *, per_reason_limit: int = 8) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    by_reason: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in row_records:
        flags = [field for field in REASON_FIELDS if _norm_bool(row.get(field))]
        flags.append(_norm_text_or_none(row.get("primary_reason")) or "unknown")
        for reason in flags:
            bucket = by_reason[reason]
            if len(bucket) >= per_reason_limit:
                continue
            bucket.append(
                {
                    "reason_bucket": reason,
                    "artifact_id": row.get("artifact_id"),
                    "resolved_dynamic_run_id": row.get("resolved_dynamic_run_id"),
                    "artifact_type": row.get("artifact_type"),
                    "host_path_exists": row.get("host_path_exists"),
                    "db_reference_names_csv": row.get("db_reference_names_csv"),
                    "status_reason": row.get("status_reason"),
                    "host_path": row.get("host_path"),
                }
            )
    for reason in sorted(by_reason):
        samples.extend(by_reason[reason])
    return samples


def collect_artifact_registry_dynamic_dangling_report(
    run_sql: RunSql,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    schema_rows, discovered_tables = _schema_inventory(run_sql)
    totals = _collect_totals(run_sql)
    raw_rows = _rows(
        run_sql,
        _dangling_row_sql(discovered_tables),
        query_name="artifact_registry_dynamic_dangling.dangling_rows",
    )
    row_records = [_classify_row(row, repo_root=repo_root) for row in raw_rows]
    run_rows = _build_run_rows(row_records)
    reason_counts = _build_reason_counts(
        row_records,
        linked_dynamic_registry_rows=totals["linked_dynamic_registry_rows"],
        dangling_dynamic_registry_rows=totals["dangling_dynamic_registry_rows"],
    )
    reason_samples = _build_reason_samples(row_records)

    primary_counts = Counter(_norm_text_or_none(row.get("primary_reason")) or "unknown" for row in row_records)
    age_counts = Counter(_norm_text_or_none(row.get("age_bucket")) or "unknown" for row in row_records)
    workspace_counts = Counter(_norm_text_or_none(row.get("host_workspace_prefix")) or "(blank)" for row in row_records)
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "repo_root": str(repo_root.resolve()),
        "total_artifact_registry_rows_reviewed": len(row_records),
        "distinct_dynamic_run_count": len(run_rows),
        "linked_dynamic_registry_rows": totals["linked_dynamic_registry_rows"],
        "dangling_dynamic_registry_rows": totals["dangling_dynamic_registry_rows"],
        "reason_flag_counts": {
            row["reason_bucket"]: row["count"] for row in reason_counts if row["reason_kind"] == "flag"
        },
        "primary_reason_counts": dict(sorted(primary_counts.items())),
        "age_bucket_counts": dict(sorted(age_counts.items())),
        "workspace_prefix_counts": dict(sorted(workspace_counts.items())),
        "output_files": list(OUTPUT_FILES),
        "schema_tables_discovered": [row["table_name"] for row in schema_rows],
        "no_db_writes": True,
        "report_scope": "artifact_registry dangling dynamic rows only",
        "assumptions": [
            "dynamic_sessions is the authoritative session linkage surface for dynamic registry rows",
            "analysis_* and ml_* tables are treated as corroborating references, not authoritative session truth",
            "filesystem existence checks use host_path only and do not infer remote/offline storage",
        ],
    }
    return {
        "summary": summary,
        "dynamic_schema_inventory": schema_rows,
        "dynamic_dangling_rows": row_records,
        "dynamic_dangling_runs": run_rows,
        "dynamic_dangling_reason_counts": reason_counts,
        "dynamic_dangling_reason_samples": reason_samples,
    }


def write_artifact_registry_dynamic_dangling_bundle(report: Mapping[str, Any], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []
    json_path = output_dir / "summary.json"
    json_path.write_text(json.dumps(report.get("summary") or {}, indent=2, sort_keys=True, default=str), encoding="utf-8")
    files.append(json_path)

    csv_map = {
        "dynamic_schema_inventory.csv": report.get("dynamic_schema_inventory") or [],
        "dynamic_dangling_rows.csv": report.get("dynamic_dangling_rows") or [],
        "dynamic_dangling_runs.csv": report.get("dynamic_dangling_runs") or [],
        "dynamic_dangling_reason_counts.csv": report.get("dynamic_dangling_reason_counts") or [],
        "dynamic_dangling_reason_samples.csv": report.get("dynamic_dangling_reason_samples") or [],
    }
    for filename, rows in csv_map.items():
        path = output_dir / filename
        row_list = list(rows)
        if not row_list:
            path.write_text("", encoding="utf-8")
            files.append(path)
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
        files.append(path)
    return files


__all__ = [
    "OUTPUT_FILES",
    "collect_artifact_registry_dynamic_dangling_report",
    "write_artifact_registry_dynamic_dangling_bundle",
]
