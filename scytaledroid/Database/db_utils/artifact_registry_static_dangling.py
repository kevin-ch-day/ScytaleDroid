"""Read-only static dangling registry audit helpers.

Correlates ``artifact_registry`` rows that are dangling on the static side
against surviving static DB surfaces and the local filesystem. This module does
not perform any DML/DDL.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RunSql = Callable[..., Any]

OUTPUT_FILES: tuple[str, ...] = (
    "summary.json",
    "static_schema_inventory.csv",
    "static_dangling_rows.csv",
    "static_dangling_runs.csv",
    "static_dangling_reason_counts.csv",
    "static_dangling_reason_samples.csv",
)

STATIC_TABLE_ORDER: tuple[str, ...] = (
    "static_analysis_runs",
    "static_analysis_sessions",
    "static_session_run_links",
    "static_analysis_findings",
    "static_permission_matrix",
    "static_string_summary",
    "static_findings_summary",
    "permission_audit_snapshots",
    "runs",
)

DB_REFERENCE_FIELDS: tuple[str, ...] = (
    "has_static_session_run_link",
    "has_static_analysis_findings",
    "has_static_permission_matrix",
    "has_static_string_summary",
    "has_static_findings_summary",
    "has_permission_audit_snapshot",
    "has_legacy_runs",
)

CANONICAL_REFERENCE_FIELDS: tuple[str, ...] = (
    "has_static_session_run_link",
    "has_static_analysis_findings",
    "has_static_permission_matrix",
    "has_static_string_summary",
    "has_static_findings_summary",
    "has_permission_audit_snapshot",
)

REASON_FIELDS: tuple[str, ...] = (
    "missing_static_run",
    "missing_host_file",
    "host_file_exists_but_db_detached",
    "legacy_runs_row_present",
    "canonical_db_reference_present",
    "malformed_static_run_id",
    "unknown_needs_review",
)

CORE_BUNDLE_ARTIFACT_TYPES: tuple[str, ...] = (
    "dep_snapshot",
    "static_run_manifest",
    "manifest_evidence",
    "static_baseline_json",
    "static_dynamic_plan_json",
    "static_report",
)

_TIMESTAMP_HINT_RE = re.compile(r"-(\d{8}T\d{6}Z)\.json$", re.IGNORECASE)


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


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _infer_host_path_family(host_path: str | None) -> str | None:
    hp = _norm_text_or_none(host_path)
    if not hp:
        return None
    path = hp.replace("\\", "/")
    if "/data/static_analysis/reports/latest/" in path:
        return "static_reports_latest"
    if "/data/static_analysis/baseline/" in path:
        return "static_baseline_json"
    if "/data/static_analysis/dynamic_plan/" in path:
        return "static_dynamic_plan_json"
    if "/evidence/static_runs/" in path and path.endswith("/run_manifest.json"):
        return "static_run_manifest"
    if "/evidence/static_runs/" in path and path.endswith("/manifest_evidence.json"):
        return "manifest_evidence"
    if "/evidence/static_runs/" in path and path.endswith("/dep.json"):
        return "dep_snapshot"
    if "/output/evidence/static_runs/" in path:
        return "output_static_evidence"
    return "other"


def _workspace_prefix(host_path: str | None) -> str | None:
    hp = _norm_text_or_none(host_path)
    if not hp:
        return None
    marker = "/output/"
    if marker in hp:
        return hp.split(marker, 1)[0]
    return str(Path(hp).parent)


def _timestamp_hint_from_path(host_path: str | None) -> str | None:
    hp = _norm_text_or_none(host_path)
    if not hp:
        return None
    match = _TIMESTAMP_HINT_RE.search(hp.replace("\\", "/"))
    if not match:
        return None
    return match.group(1)


def _recover_run_manifest_context(repo_root: Path, run_id: str) -> dict[str, Any]:
    manifest_path = repo_root / "evidence" / "static_runs" / run_id / "run_manifest.json"
    manifest_exists = manifest_path.is_file()
    payload = _read_json(manifest_path) if manifest_exists else None
    return {
        "recovered_run_manifest_path": str(manifest_path) if manifest_exists else None,
        "recovered_run_manifest_exists": manifest_exists,
        "recovered_package_name": _norm_text_or_none((payload or {}).get("package_name")),
        "recovered_display_name": _norm_text_or_none((payload or {}).get("display_name")),
        "recovered_version_name": _norm_text_or_none((payload or {}).get("version_name")),
        "recovered_version_code": _norm_text_or_none((payload or {}).get("version_code")),
        "recovered_profile_key": _norm_text_or_none((payload or {}).get("profile_key")),
        "recovered_scenario_id": _norm_text_or_none((payload or {}).get("scenario_id")),
        "recovered_run_grade": _norm_text_or_none((payload or {}).get("run_grade")),
        "recovered_base_apk_sha256": _norm_text_or_none((payload or {}).get("base_apk_sha256") or (payload or {}).get("apk_sha256")),
    }


def _schema_inventory(run_sql: RunSql) -> tuple[list[dict[str, Any]], set[str]]:
    rows = _rows(
        run_sql,
        """
        SELECT table_name, column_name, column_type
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name IN (
            'static_analysis_runs',
            'static_analysis_sessions',
            'static_session_run_links',
            'static_analysis_findings',
            'static_permission_matrix',
            'static_string_summary',
            'static_findings_summary',
            'permission_audit_snapshots',
            'runs'
          )
        ORDER BY table_name, ordinal_position
        """,
        query_name="artifact_registry_static_dangling.schema_inventory",
    )
    by_table: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_table[_norm_text(row.get("table_name"))].append(row)

    schema_rows: list[dict[str, Any]] = []
    discovered_tables: set[str] = set()
    for table_name in STATIC_TABLE_ORDER:
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
                "static_run_id_present": "static_run_id" in column_names,
                "run_id_present": "run_id" in column_names,
                "session_stamp_present": "session_stamp" in column_names,
                "session_label_present": "session_label" in column_names,
                "package_name_present": "package_name" in column_names,
            }
        )
    return schema_rows, discovered_tables


def _collect_totals(run_sql: RunSql) -> dict[str, int]:
    row = _row(
        run_sql,
        """
        SELECT
          SUM(CASE WHEN run_type = 'static' AND link_state = 'linked' THEN 1 ELSE 0 END) AS linked_static_registry_rows,
          SUM(CASE WHEN run_type = 'static' AND link_state = 'dangling_static_run' THEN 1 ELSE 0 END) AS dangling_static_registry_rows
        FROM v_artifact_registry_integrity
        """,
        query_name="artifact_registry_static_dangling.static_totals",
    )
    return {
        "linked_static_registry_rows": int(row.get("linked_static_registry_rows") or 0),
        "dangling_static_registry_rows": int(row.get("dangling_static_registry_rows") or 0),
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
        "v.static_run_id",
        "v.resolved_static_run_id",
        "v.link_state",
        "v.linkage_resolution_path",
        "v.artifact_type",
        "v.origin",
        "v.host_path",
        "v.created_at_utc",
        "v.status_reason",
        "JSON_UNQUOTE(JSON_EXTRACT(v.meta_json, '$.package_name')) AS meta_package_name",
        "COALESCE(v.session_stamp, JSON_UNQUOTE(JSON_EXTRACT(v.meta_json, '$.session_stamp'))) AS meta_session_stamp",
        "JSON_UNQUOTE(JSON_EXTRACT(v.meta_json, '$.session_label')) AS meta_session_label",
        _exists("has_static_session_run_link", "static_session_run_links", "t.static_run_id = v.resolved_static_run_id"),
        _exists("has_static_analysis_findings", "static_analysis_findings", "t.run_id = v.resolved_static_run_id"),
        _exists("has_static_permission_matrix", "static_permission_matrix", "t.run_id = v.resolved_static_run_id"),
        _exists("has_static_string_summary", "static_string_summary", "t.static_run_id = v.resolved_static_run_id"),
        _exists("has_static_findings_summary", "static_findings_summary", "t.static_run_id = v.resolved_static_run_id"),
        _exists("has_permission_audit_snapshot", "permission_audit_snapshots", "t.static_run_id = v.resolved_static_run_id"),
        _exists("has_legacy_runs", "runs", "t.run_id = v.resolved_static_run_id"),
    ]
    return f"""
        SELECT
          {", ".join(select_bits)}
        FROM v_artifact_registry_integrity v
        WHERE v.run_type = 'static'
          AND v.link_state = 'dangling_static_run'
        ORDER BY v.created_at_utc, v.artifact_id
    """


def _classify_row(row: Mapping[str, Any], *, repo_root: Path) -> dict[str, Any]:
    resolved_static_run_id = row.get("resolved_static_run_id")
    static_run_id_value: int | None
    try:
        static_run_id_value = int(resolved_static_run_id) if resolved_static_run_id is not None else None
    except (TypeError, ValueError):
        static_run_id_value = None
    host_path = _norm_text_or_none(row.get("host_path"))
    file_exists = _path_exists(host_path)
    malformed = static_run_id_value is None
    has_canonical_db_reference = any(_norm_bool(row.get(field)) for field in CANONICAL_REFERENCE_FIELDS)
    has_legacy_runs = _norm_bool(row.get("has_legacy_runs"))

    if malformed:
        primary_reason = "malformed_static_run_id"
    elif has_canonical_db_reference:
        primary_reason = "canonical_db_residue"
    elif has_legacy_runs and file_exists is True:
        primary_reason = "legacy_mirror_only_with_file"
    elif has_legacy_runs and file_exists is False:
        primary_reason = "legacy_mirror_only_file_missing"
    elif file_exists is True:
        primary_reason = "file_present_db_detached"
    elif file_exists is False:
        primary_reason = "truly_detached"
    else:
        primary_reason = "unknown_needs_review"

    reason_flags: dict[str, bool] = {
        "missing_static_run": True,
        "missing_host_file": file_exists is False,
        "host_file_exists_but_db_detached": (file_exists is True) and not has_canonical_db_reference,
        "legacy_runs_row_present": has_legacy_runs,
        "canonical_db_reference_present": has_canonical_db_reference,
        "malformed_static_run_id": malformed,
        "unknown_needs_review": primary_reason == "unknown_needs_review",
    }
    db_reference_names = [field for field in DB_REFERENCE_FIELDS if _norm_bool(row.get(field))]
    repo_root_text = str(repo_root.resolve())
    under_repo_root = bool(host_path and host_path.startswith(repo_root_text))
    return {
        "artifact_id": int(row.get("artifact_id") or 0),
        "run_type": _norm_text_or_none(row.get("run_type")),
        "run_id": _norm_text_or_none(row.get("run_id")),
        "static_run_id": static_run_id_value,
        "resolved_static_run_id": static_run_id_value,
        "artifact_type": _norm_text_or_none(row.get("artifact_type")),
        "origin": _norm_text_or_none(row.get("origin")),
        "host_path": host_path,
        "host_path_family": _infer_host_path_family(host_path),
        "host_workspace_prefix": _workspace_prefix(host_path),
        "host_path_exists": file_exists,
        "host_path_under_repo_root": under_repo_root,
        "created_at_utc": _norm_text_or_none(row.get("created_at_utc")),
        "age_bucket": _age_bucket(row.get("created_at_utc")),
        "status_reason": _norm_text_or_none(row.get("status_reason")),
        "link_state": _norm_text_or_none(row.get("link_state")),
        "linkage_resolution_path": _norm_text_or_none(row.get("linkage_resolution_path")),
        "meta_package_name": _norm_text_or_none(row.get("meta_package_name")),
        "meta_session_stamp": _norm_text_or_none(row.get("meta_session_stamp")),
        "meta_session_label": _norm_text_or_none(row.get("meta_session_label")),
        "has_any_static_db_reference": has_canonical_db_reference,
        "db_reference_names_csv": ",".join(db_reference_names),
        "primary_reason": primary_reason,
        **reason_flags,
        **{field: _norm_bool(row.get(field)) for field in DB_REFERENCE_FIELDS},
    }


def _build_run_rows(row_records: Sequence[Mapping[str, Any]], *, repo_root: Path) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    reason_counter_by_run: dict[str, Counter[str]] = defaultdict(Counter)
    artifact_counter_by_run: dict[str, Counter[str]] = defaultdict(Counter)
    path_family_counter_by_run: dict[str, Counter[str]] = defaultdict(Counter)
    timestamp_hints_by_run: dict[str, set[str]] = defaultdict(set)
    for row in row_records:
        run_id = str(row.get("resolved_static_run_id") or row.get("run_id") or "(blank)")
        group = grouped.setdefault(
            run_id,
            {
                "resolved_static_run_id": run_id,
                "row_count": 0,
                "artifact_type_count": 0,
                "artifact_types_csv": "",
                "path_family_count": 0,
                "path_families_csv": "",
                "primary_reason": row.get("primary_reason"),
                "age_bucket": row.get("age_bucket"),
                "created_at_min_utc": row.get("created_at_utc"),
                "created_at_max_utc": row.get("created_at_utc"),
                "host_path_exists_true": 0,
                "host_path_exists_false": 0,
                "db_reference_names_csv": "",
                "meta_package_name": row.get("meta_package_name"),
                "meta_session_stamp": row.get("meta_session_stamp"),
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
        path_family_counter_by_run[run_id][_norm_text_or_none(row.get("host_path_family")) or ""] += 1
        reason_counter_by_run[run_id][_norm_text_or_none(row.get("primary_reason")) or "unknown"] += 1
        hint = _timestamp_hint_from_path(_norm_text_or_none(row.get("host_path")))
        if hint:
            timestamp_hints_by_run[run_id].add(hint)
    out: list[dict[str, Any]] = []
    for run_id, group in grouped.items():
        artifact_types = artifact_counter_by_run[run_id]
        path_families = path_family_counter_by_run[run_id]
        reasons = reason_counter_by_run[run_id]
        dominant_reason = max(reasons.items(), key=lambda item: (item[1], item[0]))[0] if reasons else None
        manifest_context = _recover_run_manifest_context(repo_root, run_id) if run_id.isdigit() else {
            "recovered_run_manifest_path": None,
            "recovered_run_manifest_exists": False,
            "recovered_package_name": None,
            "recovered_display_name": None,
            "recovered_version_name": None,
            "recovered_version_code": None,
            "recovered_profile_key": None,
            "recovered_scenario_id": None,
            "recovered_run_grade": None,
            "recovered_base_apk_sha256": None,
        }
        duplicate_types = sorted(kind for kind, count in artifact_types.items() if kind and int(count) > 1)
        missing_core_types = sorted(kind for kind in CORE_BUNDLE_ARTIFACT_TYPES if artifact_types.get(kind, 0) <= 0)
        group["artifact_type_count"] = len(artifact_types)
        group["artifact_types_csv"] = ",".join(sorted(artifact_types))
        group["path_family_count"] = len(path_families)
        group["path_families_csv"] = ",".join(sorted(path_families))
        group["dominant_primary_reason"] = dominant_reason
        group["primary_reason_distribution"] = json.dumps(dict(sorted(reasons.items())), sort_keys=True)
        group["path_timestamp_hints_csv"] = ",".join(sorted(timestamp_hints_by_run.get(run_id) or ()))
        group["duplicate_artifact_rows"] = sum(max(0, int(count) - 1) for count in artifact_types.values())
        group["duplicate_artifact_types_csv"] = ",".join(duplicate_types)
        group["core_bundle_artifact_type_count"] = sum(1 for kind in CORE_BUNDLE_ARTIFACT_TYPES if artifact_types.get(kind, 0) > 0)
        group["missing_core_artifact_types_csv"] = ",".join(missing_core_types)
        group["core_bundle_complete"] = not missing_core_types
        group.update(manifest_context)
        out.append(group)
    out.sort(key=lambda row: (str(row.get("created_at_min_utc") or ""), str(row.get("resolved_static_run_id") or "")))
    return out


def _build_reason_counts(
    row_records: Sequence[Mapping[str, Any]],
    *,
    linked_static_registry_rows: int,
    dangling_static_registry_rows: int,
) -> list[dict[str, Any]]:
    primary_counts = Counter(_norm_text_or_none(row.get("primary_reason")) or "unknown" for row in row_records)
    flag_counts = Counter()
    for row in row_records:
        for field in REASON_FIELDS:
            if _norm_bool(row.get(field)):
                flag_counts[field] += 1
    counts: list[dict[str, Any]] = [
        {"reason_bucket": "linked_static_registry_rows", "count": int(linked_static_registry_rows), "reason_kind": "baseline"},
        {"reason_bucket": "dangling_static_registry_rows", "count": int(dangling_static_registry_rows), "reason_kind": "baseline"},
    ]
    for field in REASON_FIELDS:
        counts.append({"reason_bucket": field, "count": int(flag_counts.get(field, 0)), "reason_kind": "flag"})
    for field in (
        "canonical_db_residue",
        "legacy_mirror_only_with_file",
        "legacy_mirror_only_file_missing",
        "file_present_db_detached",
        "truly_detached",
        "malformed_static_run_id",
        "unknown_needs_review",
    ):
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
                    "resolved_static_run_id": row.get("resolved_static_run_id"),
                    "artifact_type": row.get("artifact_type"),
                    "host_path_family": row.get("host_path_family"),
                    "host_path_exists": row.get("host_path_exists"),
                    "db_reference_names_csv": row.get("db_reference_names_csv"),
                    "status_reason": row.get("status_reason"),
                    "host_path": row.get("host_path"),
                }
            )
    for reason in sorted(by_reason):
        samples.extend(by_reason[reason])
    return samples


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    keys: list[str] = sorted({str(key) for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in keys})


def collect_artifact_registry_static_dangling_report(
    run_sql: RunSql,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    schema_rows, discovered_tables = _schema_inventory(run_sql)
    totals = _collect_totals(run_sql)
    dangling_rows_raw = _rows(
        run_sql,
        _dangling_row_sql(discovered_tables),
        query_name="artifact_registry_static_dangling.dangling_rows",
    )
    row_records = [_classify_row(row, repo_root=repo_root) for row in dangling_rows_raw]
    run_rows = _build_run_rows(row_records, repo_root=repo_root)
    reason_counts = _build_reason_counts(
        row_records,
        linked_static_registry_rows=totals["linked_static_registry_rows"],
        dangling_static_registry_rows=totals["dangling_static_registry_rows"],
    )
    reason_samples = _build_reason_samples(row_records)
    primary_reason_counts = Counter(_norm_text_or_none(row.get("primary_reason")) or "unknown" for row in row_records)
    reason_flag_counts = Counter()
    for row in row_records:
        for field in REASON_FIELDS:
            if _norm_bool(row.get(field)):
                reason_flag_counts[field] += 1
    path_family_counts = Counter(_norm_text_or_none(row.get("host_path_family")) or "unknown" for row in row_records)
    artifact_type_counts = Counter(_norm_text_or_none(row.get("artifact_type")) or "unknown" for row in row_records)
    linkage_resolution_counts = Counter(_norm_text_or_none(row.get("linkage_resolution_path")) or "unknown" for row in row_records)
    recovered_packages = {
        _norm_text_or_none(row.get("recovered_package_name"))
        for row in run_rows
        if _norm_text_or_none(row.get("recovered_package_name"))
    }

    summary = {
        **totals,
        "distinct_static_run_count": len({str(row.get("resolved_static_run_id")) for row in row_records if row.get("resolved_static_run_id") is not None}),
        "distinct_recovered_package_count": len(recovered_packages),
        "runs_with_recovered_manifest_context": sum(1 for row in run_rows if _norm_bool(row.get("recovered_run_manifest_exists"))),
        "complete_core_bundle_run_count": sum(1 for row in run_rows if _norm_bool(row.get("core_bundle_complete"))),
        "partial_core_bundle_run_count": sum(1 for row in run_rows if not _norm_bool(row.get("core_bundle_complete"))),
        "runs_with_duplicate_artifact_types": sum(1 for row in run_rows if _norm_text_or_none(row.get("duplicate_artifact_types_csv"))),
        "schema_tables_discovered": [row["table_name"] for row in schema_rows],
        "primary_reason_counts": dict(sorted(primary_reason_counts.items())),
        "reason_flag_counts": dict(sorted(reason_flag_counts.items())),
        "path_family_counts": dict(sorted(path_family_counts.items())),
        "artifact_type_counts": dict(sorted(artifact_type_counts.items())),
        "linkage_resolution_path_counts": dict(sorted(linkage_resolution_counts.items())),
        "rows_with_legacy_runs_overlap": int(reason_flag_counts.get("legacy_runs_row_present", 0)),
        "rows_with_canonical_db_residue": int(reason_flag_counts.get("canonical_db_reference_present", 0)),
    }
    return {
        "summary": summary,
        "static_schema_inventory": schema_rows,
        "static_dangling_rows": row_records,
        "static_dangling_runs": run_rows,
        "static_dangling_reason_counts": reason_counts,
        "static_dangling_reason_samples": reason_samples,
    }


def write_artifact_registry_static_dangling_bundle(report: Mapping[str, Any], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, payload in (
        ("summary.json", report.get("summary") or {}),
        ("static_schema_inventory.csv", report.get("static_schema_inventory") or []),
        ("static_dangling_rows.csv", report.get("static_dangling_rows") or []),
        ("static_dangling_runs.csv", report.get("static_dangling_runs") or []),
        ("static_dangling_reason_counts.csv", report.get("static_dangling_reason_counts") or []),
        ("static_dangling_reason_samples.csv", report.get("static_dangling_reason_samples") or []),
    ):
        path = output_dir / name
        if name.endswith(".json"):
            path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
        else:
            _write_csv(path, payload if isinstance(payload, Sequence) else [])
        written.append(path)
    return written


__all__ = [
    "OUTPUT_FILES",
    "collect_artifact_registry_static_dangling_report",
    "write_artifact_registry_static_dangling_bundle",
]
