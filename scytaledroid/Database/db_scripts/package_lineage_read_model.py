"""Shared package/version/hash lineage read model for DB operator scripts.

This module intentionally contains no CLI rendering and performs no writes.
Scripts under ``scripts/db`` use it to keep package lineage, byte
availability, static coverage, dynamic coverage, and target-state semantics in
one place while preserving stable script entrypoint paths.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def fetch_base_rows(core_q: Any, *, package_name: str | None) -> list[dict[str, Any]]:
    params: list[Any] = []
    package_filter = ""
    if package_name:
        package_filter = "AND LOWER(TRIM(r.package_name)) = %s"
        params.append(str(package_name).strip().lower())
    return list(
        core_q.run_sql(
            f"""
            SELECT
              r.apk_id,
              LOWER(TRIM(r.package_name)) AS package_name,
              COALESCE(NULLIF(a.display_name, ''), LOWER(TRIM(r.package_name))) AS display_name,
              r.version_code,
              r.version_name,
              LOWER(TRIM(r.sha256)) AS base_apk_sha256,
              h.storage_root_id,
              h.local_rel_path,
              sr.data_root
            FROM android_apk_repository r
            LEFT JOIN apps a ON LOWER(TRIM(a.package_name)) = LOWER(TRIM(r.package_name))
            LEFT JOIN harvest_artifact_paths h ON h.apk_id = r.apk_id
            LEFT JOIN harvest_storage_roots sr ON sr.root_id = h.storage_root_id
            WHERE r.sha256 IS NOT NULL
              AND COALESCE(r.is_split_member, 0) = 0
              {package_filter}
            GROUP BY
              r.apk_id,
              LOWER(TRIM(r.package_name)),
              COALESCE(NULLIF(a.display_name, ''), LOWER(TRIM(r.package_name))),
              r.version_code,
              r.version_name,
              LOWER(TRIM(r.sha256)),
              h.storage_root_id,
              h.local_rel_path,
              sr.data_root
            """,
            tuple(params),
            fetch="all",
            dictionary=True,
            query_name="package_lineage_read_model.base_rows",
        )
        or []
    )


def fetch_static_coverage(core_q: Any) -> dict[str, dict[str, Any]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS static_runs,
          SUM(CASE
                WHEN status='COMPLETED'
                 AND run_class='CANONICAL'
                 AND COALESCE(identity_valid,0)=1
                THEN 1 ELSE 0
              END) AS canonical_completed_identity_valid,
          MAX(static_session_id) AS latest_static_session
        FROM static_analysis_runs
        WHERE base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.static_coverage",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def fetch_dynamic_coverage(core_q: Any) -> dict[str, dict[str, Any]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(ds.base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS dynamic_sessions,
          SUM(CASE WHEN ds.static_run_id IS NULL THEN 1 ELSE 0 END) AS dynamic_unlinked_sessions,
          SUM(CASE
                WHEN sar.id IS NOT NULL
                 AND LOWER(TRIM(sar.base_apk_sha256)) = LOWER(TRIM(ds.base_apk_sha256))
                 AND sar.status = 'COMPLETED'
                 AND sar.run_class = 'CANONICAL'
                 AND COALESCE(sar.identity_valid, 0) = 1
                THEN 1 ELSE 0
              END) AS dynamic_linked_sessions
        FROM dynamic_sessions ds
        LEFT JOIN static_analysis_runs sar ON sar.id = ds.static_run_id
        WHERE ds.base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(ds.base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.dynamic_coverage",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def fetch_apk_sets_by_hash(core_q: Any) -> dict[str, dict[str, Any]]:
    if not table_exists(core_q, "apk_sets"):
        return {}
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS install_sets_seen,
          MIN(apk_set_id) AS apk_set_id,
          MIN(artifact_set_hash) AS artifact_set_hash,
          MAX(member_count) AS member_count,
          MAX(split_count) AS split_count
        FROM apk_sets
        WHERE base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.apk_sets",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def fetch_same_version_hash_drift_keys(core_q: Any) -> set[tuple[str, str, str]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(package_name)) AS package_name,
          COALESCE(CAST(version_code AS CHAR), '') AS version_code,
          COALESCE(version_name, '') AS version_name,
          COUNT(DISTINCT LOWER(TRIM(sha256))) AS hashes
        FROM android_apk_repository
        WHERE sha256 IS NOT NULL
          AND COALESCE(is_split_member, 0) = 0
        GROUP BY
          LOWER(TRIM(package_name)),
          COALESCE(CAST(version_code AS CHAR), ''),
          COALESCE(version_name, '')
        HAVING hashes > 1
        """,
        fetch="all",
        dictionary=True,
        query_name="package_lineage_read_model.same_version_drift",
    ) or []
    return {
        (
            str(row.get("package_name") or "").lower(),
            str(row.get("version_code") or ""),
            str(row.get("version_name") or ""),
        )
        for row in rows
    }


def table_exists(core_q: Any, table_name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        """,
        (table_name,),
        fetch="one_dict",
        query_name="package_lineage_read_model.table_exists",
    )
    return int((row or {}).get("n") or 0) > 0


def recorded_abs_path(row: dict[str, Any]) -> Path | None:
    raw = str(row.get("local_rel_path") or "").strip()
    if not raw:
        return None
    local = Path(raw).expanduser()
    if local.is_absolute():
        return local
    root = str(row.get("data_root") or "").strip()
    if root:
        return Path(root).expanduser() / local
    return Path.cwd() / local


def path_exists(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and Path(text).expanduser().exists())


def norm_sha(value: Any) -> str:
    return str(value or "").strip().lower()


def byte_status(
    *,
    recorded_exists: bool,
    canonical_exists: bool,
    recorded_root_exists: bool,
    recorded_location_known: bool,
) -> str:
    if recorded_exists and canonical_exists:
        return "available_recorded_and_canonical"
    if canonical_exists:
        return "available_canonical"
    if recorded_exists:
        return "available_recorded"
    if not recorded_location_known:
        return "missing_no_recorded_location"
    if recorded_root_exists:
        return "missing_current_root_file"
    return "missing_old_root"


def split_status(*, set_info: dict[str, Any], byte_status: str) -> str:
    if set_info:
        return "install_set_known"
    if byte_status.startswith("available"):
        return "base_only_or_split_context_missing"
    return "unknown_until_bytes_restored"


def target_reason(
    *,
    exact_static: int,
    byte_status: str,
    dynamic_sessions: int,
    dynamic_unlinked: int,
    same_version_hash_drift: bool,
) -> str:
    if exact_static > 0 and dynamic_unlinked > 0:
        return "dynamic_static_gap"
    if exact_static > 0 and not byte_status.startswith("available"):
        return "artifact_lifecycle_gap"
    if exact_static > 0 and byte_status == "available_recorded":
        return "artifact_lifecycle_gap"
    if exact_static == 0 and dynamic_sessions > 0:
        return "dynamic_static_gap"
    if same_version_hash_drift:
        return "same_version_hash_drift_review"
    if exact_static == 0:
        return "new_hash_seen"
    return "covered"


def target_status(
    *,
    exact_static: int,
    byte_status: str,
    split_status: str,
    dynamic_unlinked: int,
    same_version_hash_drift: bool,
) -> str:
    if exact_static > 0 and dynamic_unlinked > 0:
        return "link_repair_preview_available"
    if exact_static > 0 and byte_status == "available_recorded":
        return "rebuild_canonical_store"
    if exact_static > 0 and byte_status == "missing_old_root":
        return "blocked_missing_bytes"
    if exact_static > 0 and byte_status in {"missing_current_root_file", "missing_no_recorded_location"}:
        return "artifact_lifecycle_gap"
    if exact_static > 0 and not same_version_hash_drift:
        return "covered"
    if same_version_hash_drift and exact_static > 0:
        return "review"
    if byte_status == "missing_old_root":
        return "blocked_missing_bytes"
    if byte_status in {"missing_current_root_file", "missing_no_recorded_location"}:
        return "needs_reharvest"
    if split_status == "base_only_or_split_context_missing":
        return "blocked_split_context"
    if byte_status.startswith("available"):
        return "ready"
    return "blocked_missing_bytes"


def target_priority(*, reason: str, target_status: str, dynamic_sessions: int) -> int:
    if target_status == "ready" and reason == "dynamic_static_gap":
        return 10
    if target_status == "link_repair_preview_available":
        return 20
    if target_status == "blocked_missing_bytes" and reason == "dynamic_static_gap":
        return 30
    if target_status == "needs_reharvest" and reason == "dynamic_static_gap":
        return 35
    if target_status == "ready":
        return 40
    if target_status == "review":
        return 50
    if target_status == "rebuild_canonical_store":
        return 55
    if target_status == "artifact_lifecycle_gap":
        return 56
    if target_status.startswith("blocked"):
        return 60 if dynamic_sessions else 70
    return 90


def operator_action(target_status: str) -> str:
    return {
        "ready": "Run exact static analysis",
        "blocked_missing_bytes": "Restore old root",
        "needs_reharvest": "Reharvest current app",
        "artifact_lifecycle_gap": "Restore or reharvest bytes",
        "blocked_split_context": "Restore split context or use explicit base-only mode",
        "link_repair_preview_available": "Preview dynamic link repair",
        "rebuild_canonical_store": "Rebuild canonical SHA store",
        "covered": "No action needed",
        "review": "Review same-version hash drift",
    }.get(target_status, "Review target state")
