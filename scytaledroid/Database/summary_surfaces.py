"""Helpers for DB-backed summary read surfaces and materialized caches."""

from __future__ import annotations

from datetime import UTC, datetime

from scytaledroid.Database.db_core import database_session, run_sql
from scytaledroid.Database.db_queries.analysis.schema import (
    ALTER_WEB_STATIC_DYNAMIC_APP_SUMMARY_CACHE_NORMALIZED_RUNTIME,
    CREATE_WEB_STATIC_DYNAMIC_APP_SUMMARY_CACHE,
)

STATIC_DYNAMIC_SUMMARY_VIEW = "v_web_static_dynamic_app_summary"
STATIC_DYNAMIC_SUMMARY_CACHE = "web_static_dynamic_app_summary_cache"
STATIC_DYNAMIC_SUMMARY_REQUIRED_RUNTIME_COLUMNS = (
    "dynamic_technical_validity_state",
    "dynamic_quota_state",
    "dynamic_cohort_eligibility_state",
)


def static_dynamic_summary_relation_has_required_runtime_columns(
    relation: str,
    *,
    runner=run_sql,
) -> bool:
    """Return True when the named summary relation exposes normalized runtime-state columns."""

    try:
        placeholders = ", ".join(["%s"] * len(STATIC_DYNAMIC_SUMMARY_REQUIRED_RUNTIME_COLUMNS))
        row = runner(
            f"""
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = %s
              AND column_name IN ({placeholders})
            """,
            (relation, *STATIC_DYNAMIC_SUMMARY_REQUIRED_RUNTIME_COLUMNS),
            fetch="one",
        )
    except Exception:
        return False
    return int(row[0] or 0) == len(STATIC_DYNAMIC_SUMMARY_REQUIRED_RUNTIME_COLUMNS) if row else False


def static_dynamic_summary_cache_status(*, runner=run_sql) -> tuple[int | None, str | None]:
    """Return cache row count and latest materialization timestamp if available."""

    try:
        exists = runner(
            """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_name = %s
            """,
            (STATIC_DYNAMIC_SUMMARY_CACHE,),
            fetch="one",
        )
    except Exception:
        return None, None

    if not exists or int(exists[0] or 0) == 0:
        return None, None

    count_row = runner(f"SELECT COUNT(*) FROM {STATIC_DYNAMIC_SUMMARY_CACHE}", fetch="one")
    ts_row = runner(
        f"SELECT MAX(materialized_at_utc) FROM {STATIC_DYNAMIC_SUMMARY_CACHE}",
        fetch="one",
    )
    count = int(count_row[0] or 0) if count_row else 0
    materialized_at = str(ts_row[0]) if ts_row and ts_row[0] is not None else None
    return count, materialized_at


def static_dynamic_summary_cache_is_stale(*, runner=run_sql) -> bool:
    """Return True when the materialized cache lags the live latest-package view."""

    count, _materialized_at = static_dynamic_summary_cache_status(runner=runner)
    if not count or count <= 0:
        return False
    try:
        cache_row = _summary_surface_freshness_row(STATIC_DYNAMIC_SUMMARY_CACHE, runner=runner)
        view_row = _summary_surface_freshness_row(STATIC_DYNAMIC_SUMMARY_VIEW, runner=runner)
    except Exception:
        return False
    if not cache_row or not view_row:
        return False

    cache_count, cache_static, cache_dynamic = _normalise_freshness_row(cache_row)
    view_count, view_static, view_dynamic = _normalise_freshness_row(view_row)
    if cache_count != view_count:
        return True
    if cache_static < view_static:
        return True
    return cache_dynamic < view_dynamic


def _summary_surface_freshness_row(relation: str, *, runner=run_sql):
    return runner(
        f"""
        SELECT
          COUNT(*) AS row_count,
          COALESCE(MAX(latest_static_run_id), 0) AS latest_static_run_id,
          MAX(latest_dynamic_started_at_utc) AS latest_dynamic_started_at_utc
        FROM {relation}
        """,
        fetch="one",
    )


def _normalise_freshness_row(row) -> tuple[int, int, str]:
    try:
        row_count = int(row[0] or 0)
    except Exception:
        row_count = 0
    try:
        static_id = int(row[1] or 0)
    except Exception:
        static_id = 0
    dynamic_started = "" if len(row) < 3 or row[2] is None else str(row[2])
    return row_count, static_id, dynamic_started


def static_dynamic_summary_cache_has_required_runtime_columns(*, runner=run_sql) -> bool:
    """Return True when the cache table exposes normalized runtime-state columns."""

    return static_dynamic_summary_relation_has_required_runtime_columns(
        STATIC_DYNAMIC_SUMMARY_CACHE,
        runner=runner,
    )


def refresh_static_dynamic_summary_cache(*, reuse_connection: bool = True) -> tuple[int, datetime]:
    """Rebuild the materialized latest-package static/dynamic summary cache."""

    materialized_at = datetime.now(UTC).replace(tzinfo=None)
    inserted = 0
    with database_session(reuse_connection=reuse_connection) as db:
        db.execute(
            CREATE_WEB_STATIC_DYNAMIC_APP_SUMMARY_CACHE,
            query_name="summary_surfaces.cache.ensure_table",
        )
        db.execute(
            ALTER_WEB_STATIC_DYNAMIC_APP_SUMMARY_CACHE_NORMALIZED_RUNTIME,
            query_name="summary_surfaces.cache.ensure_runtime_columns",
        )
        with db.transaction():
            db.execute(
                f"DELETE FROM {STATIC_DYNAMIC_SUMMARY_CACHE}",
                query_name="summary_surfaces.cache.clear",
            )
            inserted = db.execute_with_rowcount(
                f"""
                INSERT INTO {STATIC_DYNAMIC_SUMMARY_CACHE} (
                  package_name,
                  app_label,
                  category,
                  profile_key,
                  profile_label,
                  latest_apk_id,
                  latest_version_name,
                  latest_version_code,
                  latest_harvested_at,
                  latest_static_run_id,
                  latest_static_session_stamp,
                  static_source_state,
                  static_high,
                  static_med,
                  static_low,
                  static_info,
                  permission_audit_grade,
                  permission_audit_score_capped,
                  permission_audit_dangerous_count,
                  permission_audit_signature_count,
                  permission_audit_vendor_count,
                  latest_dynamic_run_id,
                  latest_dynamic_started_at_utc,
                  latest_dynamic_status,
                  latest_dynamic_grade,
                  dynamic_technical_validity_state,
                  dynamic_quota_state,
                  dynamic_cohort_eligibility_state,
                  dynamic_run_profile,
                  dynamic_interaction_level,
                  dynamic_feature_state,
                  dynamic_feature_recency_state,
                  latest_feature_dynamic_run_id,
                  dynamic_bytes_per_sec,
                  dynamic_packets_per_sec,
                  regime_dynamic_score,
                  regime_final_label,
                  regime_created_at_utc,
                  has_static_data,
                  has_dynamic_data,
                  has_regime_data,
                  summary_state,
                  materialized_at_utc
                )
                SELECT
                  package_name,
                  app_label,
                  category,
                  profile_key,
                  profile_label,
                  latest_apk_id,
                  latest_version_name,
                  latest_version_code,
                  latest_harvested_at,
                  latest_static_run_id,
                  latest_static_session_stamp,
                  static_source_state,
                  static_high,
                  static_med,
                  static_low,
                  static_info,
                  permission_audit_grade,
                  permission_audit_score_capped,
                  permission_audit_dangerous_count,
                  permission_audit_signature_count,
                  permission_audit_vendor_count,
                  latest_dynamic_run_id,
                  latest_dynamic_started_at_utc,
                  latest_dynamic_status,
                  latest_dynamic_grade,
                  dynamic_technical_validity_state,
                  dynamic_quota_state,
                  dynamic_cohort_eligibility_state,
                  dynamic_run_profile,
                  dynamic_interaction_level,
                  dynamic_feature_state,
                  dynamic_feature_recency_state,
                  latest_feature_dynamic_run_id,
                  dynamic_bytes_per_sec,
                  dynamic_packets_per_sec,
                  regime_dynamic_score,
                  regime_final_label,
                  regime_created_at_utc,
                  has_static_data,
                  has_dynamic_data,
                  has_regime_data,
                  summary_state,
                  %s
                FROM {STATIC_DYNAMIC_SUMMARY_VIEW}
                """,
                (materialized_at,),
                query_name="summary_surfaces.cache.refresh",
            )
    return int(inserted or 0), materialized_at


def preferred_static_dynamic_summary_relation(*, runner=run_sql) -> str:
    """Return the best available read surface for latest package summary rows."""

    count, _materialized_at = static_dynamic_summary_cache_status(runner=runner)
    if (
        count
        and count > 0
        and not static_dynamic_summary_cache_is_stale(runner=runner)
        and static_dynamic_summary_cache_has_required_runtime_columns(runner=runner)
    ):
        return STATIC_DYNAMIC_SUMMARY_CACHE
    return STATIC_DYNAMIC_SUMMARY_VIEW


__all__ = [
    "STATIC_DYNAMIC_SUMMARY_VIEW",
    "STATIC_DYNAMIC_SUMMARY_CACHE",
    "STATIC_DYNAMIC_SUMMARY_REQUIRED_RUNTIME_COLUMNS",
    "preferred_static_dynamic_summary_relation",
    "refresh_static_dynamic_summary_cache",
    "static_dynamic_summary_relation_has_required_runtime_columns",
    "static_dynamic_summary_cache_is_stale",
    "static_dynamic_summary_cache_has_required_runtime_columns",
    "static_dynamic_summary_cache_status",
]
