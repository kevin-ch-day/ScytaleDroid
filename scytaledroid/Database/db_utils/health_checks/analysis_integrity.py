"""Cross-pillar DB integrity checks for analysis/web consumption."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Database.db_utils.menus.sql_helpers import scalar
from scytaledroid.Database.summary_surfaces import (
    preferred_static_dynamic_summary_relation,
    static_dynamic_summary_cache_status,
)


@dataclass(frozen=True)
class AnalysisIntegritySummary:
    dynamic_runs: int | None
    dynamic_feature_rows: int | None
    dynamic_runs_missing_features: int | None
    countable_runs_missing_features: int | None
    packages_latest_run_has_features: int | None
    packages_latest_run_missing_features_older_features_exist: int | None
    packages_no_feature_rows_for_package: int | None
    dynamic_runs_with_evidence_path: int | None
    dynamic_runs_missing_local_evidence: int | None
    dynamic_artifact_host_paths_present: int | None
    dynamic_artifact_host_paths_missing: int | None
    dynamic_runs_with_dangling_static_id: int | None
    dynamic_artifact_orphan_rows: int | None
    static_artifact_orphan_rows: int | None
    app_catalog_without_analysis: int | None
    apps_without_versions: int | None
    harvested_version_pairs_missing_from_app_versions: int | None
    app_versions_missing_target_sdk: int | None
    app_versions_missing_min_sdk: int | None
    referenced_app_versions_missing_target_sdk: int | None
    referenced_app_versions_missing_min_sdk: int | None
    duplicate_app_version_code_groups: int | None
    duplicate_app_version_rows: int | None
    interrupted_permission_partial_runs: int | None
    completed_static_runs_missing_legacy_runs: int | None
    completed_static_runs_missing_risk_scores: int | None
    completed_static_runs_missing_findings_summary: int | None
    risk_surface_rows_with_both_scores: int | None
    risk_surface_score_mismatch_rows: int | None
    risk_surface_count_mismatch_rows: int | None
    risk_surface_avg_score_delta: float | None
    static_dynamic_summary_source: str
    static_dynamic_summary_cache_rows: int | None
    static_dynamic_summary_cache_materialized_at: str | None
    package_collation_variants: int | None
    legacy_non_utf8_package_tables: tuple[str, ...]
    missing_schema_objects: tuple[str, ...]


REQUIRED_ANALYSIS_SCHEMA_OBJECTS = (
    "analysis_dynamic_cohort_status",
    "v_runtime_dynamic_cohort_status_v1",
    "v_paper_dynamic_cohort_v1",
    "v_web_app_directory",
    "v_web_static_dynamic_app_summary",
    "v_web_runtime_run_index",
    "v_web_runtime_run_detail",
    "v_artifact_registry_integrity",
    "v_current_artifact_registry",
)


def _missing_schema_objects() -> tuple[str, ...]:
    missing: list[str] = []
    for name in REQUIRED_ANALYSIS_SCHEMA_OBJECTS:
        try:
            row = run_sql(
                """
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = DATABASE()
                  AND table_name = %s
                """,
                (name,),
                fetch="one",
            )
            if not row or int(row[0] or 0) == 0:
                missing.append(name)
        except Exception:
            missing.append(name)
    return tuple(missing)


def _legacy_non_utf8_package_tables() -> tuple[str, ...]:
    try:
        rows = run_sql(
            """
            SELECT table_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND column_name = 'package_name'
              AND collation_name IS NOT NULL
              AND collation_name NOT LIKE 'utf8mb4%%'
            ORDER BY table_name
            """,
            fetch="all",
        )
    except Exception:
        return ()
    return tuple(str(row[0]) for row in (rows or []) if row and row[0])


def _dynamic_evidence_path_state() -> tuple[int, int]:
    try:
        rows = run_sql(
            """
            SELECT evidence_path
            FROM dynamic_sessions
            WHERE evidence_path IS NOT NULL
              AND evidence_path <> ''
            """,
            fetch="all",
        )
    except Exception:
        return 0, 0

    paths = [Path(str(row[0])) for row in (rows or []) if row and row[0]]
    present = sum(1 for path in paths if path.exists())
    missing = len(paths) - present
    return len(paths), missing


def _dynamic_artifact_host_path_state() -> tuple[int, int]:
    try:
        rows = run_sql(
            """
            SELECT host_path
            FROM artifact_registry
            WHERE run_type = 'dynamic'
              AND host_path IS NOT NULL
              AND host_path <> ''
            """,
            fetch="all",
        )
    except Exception:
        return 0, 0

    paths = [Path(str(row[0])) for row in (rows or []) if row and row[0]]
    present = sum(1 for path in paths if path.exists())
    missing = len(paths) - present
    return present, missing


def _float_scalar(query: str) -> float | None:
    try:
        row = run_sql(query, fetch="one")
    except Exception:
        return None
    if not row:
        return None
    value = row[0]
    return float(value) if value is not None else None


def fetch_analysis_integrity_summary() -> AnalysisIntegritySummary:
    """Return cross-layer DB checks used by CLI and web-readiness audits."""
    dynamic_runs_with_evidence_path, dynamic_runs_missing_local_evidence = _dynamic_evidence_path_state()
    dynamic_artifact_host_paths_present, dynamic_artifact_host_paths_missing = _dynamic_artifact_host_path_state()
    summary_source = preferred_static_dynamic_summary_relation(runner=run_sql)
    cache_rows, cache_materialized_at = static_dynamic_summary_cache_status(runner=run_sql)

    return AnalysisIntegritySummary(
        dynamic_runs=scalar("SELECT COUNT(*) FROM dynamic_sessions"),
        dynamic_feature_rows=scalar("SELECT COUNT(*) FROM dynamic_network_features"),
        dynamic_runs_missing_features=scalar(
            """
            SELECT COUNT(*)
            FROM dynamic_sessions ds
            LEFT JOIN dynamic_network_features nf
              ON nf.dynamic_run_id = ds.dynamic_run_id
            WHERE nf.dynamic_run_id IS NULL
            """
        ),
        countable_runs_missing_features=scalar(
            """
            SELECT COUNT(*)
            FROM dynamic_sessions ds
            LEFT JOIN dynamic_network_features nf
              ON nf.dynamic_run_id = ds.dynamic_run_id
            WHERE COALESCE(ds.countable, 0) = 1
              AND nf.dynamic_run_id IS NULL
            """
        ),
        packages_latest_run_has_features=scalar(
            """
            SELECT COUNT(*)
            FROM """
            + summary_source
            + """
            WHERE dynamic_feature_recency_state = 'latest_run_has_features'
            """
        ),
        packages_latest_run_missing_features_older_features_exist=scalar(
            """
            SELECT COUNT(*)
            FROM """
            + summary_source
            + """
            WHERE dynamic_feature_recency_state = 'latest_run_missing_features_older_features_exist'
            """
        ),
        packages_no_feature_rows_for_package=scalar(
            """
            SELECT COUNT(*)
            FROM """
            + summary_source
            + """
            WHERE dynamic_feature_recency_state = 'no_feature_rows_for_package'
            """
        ),
        dynamic_runs_with_evidence_path=dynamic_runs_with_evidence_path,
        dynamic_runs_missing_local_evidence=dynamic_runs_missing_local_evidence,
        dynamic_artifact_host_paths_present=dynamic_artifact_host_paths_present,
        dynamic_artifact_host_paths_missing=dynamic_artifact_host_paths_missing,
        dynamic_runs_with_dangling_static_id=scalar(
            """
            SELECT COUNT(*)
            FROM dynamic_sessions ds
            LEFT JOIN static_analysis_runs sar
              ON sar.id = ds.static_run_id
            WHERE ds.static_run_id IS NOT NULL
              AND sar.id IS NULL
            """
        ),
        dynamic_artifact_orphan_rows=scalar(
            """
            SELECT COUNT(*)
            FROM artifact_registry ar
            LEFT JOIN dynamic_sessions ds
              ON ds.dynamic_run_id = ar.run_id
            WHERE ar.run_type = 'dynamic'
              AND ds.dynamic_run_id IS NULL
            """
        ),
        static_artifact_orphan_rows=scalar(
            """
            SELECT COUNT(*)
            FROM artifact_registry ar
            LEFT JOIN static_analysis_runs sar
              ON ar.run_id REGEXP '^[0-9]+$'
             AND sar.id = CAST(ar.run_id AS UNSIGNED)
            WHERE ar.run_type = 'static'
              AND (
                NOT ar.run_id REGEXP '^[0-9]+$'
                OR sar.id IS NULL
              )
            """
        ),
        app_catalog_without_analysis=scalar(
            """
            SELECT COUNT(*)
            FROM apps a
            LEFT JOIN vw_static_finding_surfaces_latest f
              ON f.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
            LEFT JOIN vw_static_risk_surfaces_latest r
              ON r.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
            WHERE f.static_run_id IS NULL
              AND r.static_run_id IS NULL
            """
        ),
        apps_without_versions=scalar(
            """
            SELECT COUNT(*)
            FROM apps a
            LEFT JOIN app_versions av
              ON av.app_id = a.id
            WHERE av.id IS NULL
            """
        ),
        harvested_version_pairs_missing_from_app_versions=scalar(
            """
            SELECT COUNT(*)
            FROM (
              SELECT DISTINCT r.app_id, r.version_code
              FROM android_apk_repository r
              WHERE r.app_id IS NOT NULL
                AND r.version_code IS NOT NULL
                AND r.version_code <> ''
                AND r.version_code REGEXP '^[0-9]+$'
            ) repo_versions
            LEFT JOIN app_versions av
              ON av.app_id = repo_versions.app_id
             AND av.version_code = CAST(repo_versions.version_code AS UNSIGNED)
            WHERE av.id IS NULL
            """
        ),
        app_versions_missing_target_sdk=scalar(
            """
            SELECT COUNT(*)
            FROM app_versions
            WHERE target_sdk IS NULL
            """
        ),
        app_versions_missing_min_sdk=scalar(
            """
            SELECT COUNT(*)
            FROM app_versions
            WHERE min_sdk IS NULL
            """
        ),
        referenced_app_versions_missing_target_sdk=scalar(
            """
            SELECT COUNT(*)
            FROM app_versions av
            JOIN static_analysis_runs sar ON sar.app_version_id = av.id
            WHERE av.target_sdk IS NULL
            """
        ),
        referenced_app_versions_missing_min_sdk=scalar(
            """
            SELECT COUNT(*)
            FROM app_versions av
            JOIN static_analysis_runs sar ON sar.app_version_id = av.id
            WHERE av.min_sdk IS NULL
            """
        ),
        duplicate_app_version_code_groups=scalar(
            """
            SELECT COUNT(*)
            FROM (
              SELECT app_id, version_code
              FROM app_versions
              WHERE version_code IS NOT NULL
              GROUP BY app_id, version_code
              HAVING COUNT(*) > 1
            ) x
            """
        ),
        duplicate_app_version_rows=scalar(
            """
            SELECT COALESCE(SUM(x.c), 0)
            FROM (
              SELECT COUNT(*) AS c
              FROM app_versions
              WHERE version_code IS NOT NULL
              GROUP BY app_id, version_code
              HAVING COUNT(*) > 1
            ) x
            """
        ),
        interrupted_permission_partial_runs=scalar(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs sar
            WHERE UPPER(COALESCE(sar.status, '')) IN ('FAILED', 'ABORTED')
              AND EXISTS (
                SELECT 1 FROM static_permission_matrix spm WHERE spm.run_id = sar.id
              )
              AND NOT EXISTS (
                SELECT 1 FROM permission_audit_snapshots pas WHERE pas.static_run_id = sar.id
              )
            """
        ),
        completed_static_runs_missing_legacy_runs=scalar(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            LEFT JOIN runs r
              ON r.session_stamp = sar.session_stamp
             AND r.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
            WHERE UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
              AND r.run_id IS NULL
            """
        ),
        completed_static_runs_missing_risk_scores=scalar(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            LEFT JOIN risk_scores rs
              ON rs.session_stamp = sar.session_stamp
             AND rs.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
            WHERE UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
              AND rs.id IS NULL
            """
        ),
        completed_static_runs_missing_findings_summary=scalar(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs sar
            LEFT JOIN static_findings_summary sfs ON sfs.static_run_id = sar.id
            WHERE UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
              AND sfs.id IS NULL
            """
        ),
        risk_surface_rows_with_both_scores=scalar(
            """
            SELECT COUNT(*)
            FROM vw_static_risk_surfaces_latest
            WHERE permission_run_score IS NOT NULL
              AND permission_audit_score_capped IS NOT NULL
            """
        ),
        risk_surface_score_mismatch_rows=scalar(
            """
            SELECT COUNT(*)
            FROM vw_static_risk_surfaces_latest
            WHERE permission_run_score IS NOT NULL
              AND permission_audit_score_capped IS NOT NULL
              AND ABS(permission_run_score - permission_audit_score_capped) >= 0.001
            """
        ),
        risk_surface_count_mismatch_rows=scalar(
            """
            SELECT COUNT(*)
            FROM vw_static_risk_surfaces_latest
            WHERE permission_run_score IS NOT NULL
              AND permission_audit_score_capped IS NOT NULL
              AND (
                COALESCE(permission_run_dangerous_count, 0) <> COALESCE(permission_audit_dangerous_count, 0)
                OR COALESCE(permission_run_signature_count, 0) <> COALESCE(permission_audit_signature_count, 0)
                OR COALESCE(permission_run_vendor_count, 0) <> COALESCE(permission_audit_vendor_count, 0)
              )
            """
        ),
        risk_surface_avg_score_delta=_float_scalar(
            """
            SELECT ROUND(AVG(permission_run_score - permission_audit_score_capped), 3)
            FROM vw_static_risk_surfaces_latest
            WHERE permission_run_score IS NOT NULL
              AND permission_audit_score_capped IS NOT NULL
            """
        ),
        static_dynamic_summary_source=summary_source,
        static_dynamic_summary_cache_rows=cache_rows,
        static_dynamic_summary_cache_materialized_at=cache_materialized_at,
        package_collation_variants=scalar(
            """
            SELECT COUNT(DISTINCT COLLATION_NAME)
            FROM information_schema.COLUMNS
            WHERE table_schema = DATABASE()
              AND column_name = 'package_name'
              AND COLLATION_NAME IS NOT NULL
            """
        ),
        legacy_non_utf8_package_tables=_legacy_non_utf8_package_tables(),
        missing_schema_objects=_missing_schema_objects(),
    )


__all__ = [
    "AnalysisIntegritySummary",
    "REQUIRED_ANALYSIS_SCHEMA_OBJECTS",
    "fetch_analysis_integrity_summary",
]
