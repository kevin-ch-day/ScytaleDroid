"""Cross-pillar DB integrity checks for analysis/web consumption."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Database.db_utils.menus.sql_helpers import scalar


@dataclass(frozen=True)
class AnalysisIntegritySummary:
    dynamic_runs: int | None
    dynamic_feature_rows: int | None
    dynamic_runs_missing_features: int | None
    countable_runs_missing_features: int | None
    dynamic_runs_with_dangling_static_id: int | None
    dynamic_artifact_orphan_rows: int | None
    static_artifact_orphan_rows: int | None
    app_catalog_without_analysis: int | None
    apps_without_versions: int | None
    package_collation_variants: int | None
    missing_schema_objects: tuple[str, ...]


REQUIRED_ANALYSIS_SCHEMA_OBJECTS = (
    "analysis_dynamic_cohort_status",
    "v_runtime_dynamic_cohort_status_v1",
    "v_paper_dynamic_cohort_v1",
    "v_web_app_directory",
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


def fetch_analysis_integrity_summary() -> AnalysisIntegritySummary:
    """Return cross-layer DB checks used by CLI and web-readiness audits."""
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
            LEFT JOIN static_findings_summary s
              ON s.package_name COLLATE utf8mb4_general_ci = a.package_name COLLATE utf8mb4_general_ci
            LEFT JOIN permission_audit_apps p
              ON p.package_name COLLATE utf8mb4_general_ci = a.package_name COLLATE utf8mb4_general_ci
            WHERE s.id IS NULL
              AND p.audit_id IS NULL
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
        package_collation_variants=scalar(
            """
            SELECT COUNT(DISTINCT COLLATION_NAME)
            FROM information_schema.COLUMNS
            WHERE table_schema = DATABASE()
              AND column_name = 'package_name'
              AND COLLATION_NAME IS NOT NULL
            """
        ),
        missing_schema_objects=_missing_schema_objects(),
    )


__all__ = [
    "AnalysisIntegritySummary",
    "REQUIRED_ANALYSIS_SCHEMA_OBJECTS",
    "fetch_analysis_integrity_summary",
]
