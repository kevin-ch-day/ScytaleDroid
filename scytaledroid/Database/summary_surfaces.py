"""Helpers for DB-backed summary read surfaces and materialized caches."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from scytaledroid.Database.db_core import database_session
from scytaledroid.Database.db_core import run_sql
from scytaledroid.Database.db_queries.analysis.schema import (
    CREATE_WEB_STATIC_DYNAMIC_APP_SUMMARY_CACHE,
)

STATIC_DYNAMIC_SUMMARY_VIEW = "v_web_static_dynamic_app_summary"
STATIC_DYNAMIC_SUMMARY_CACHE = "web_static_dynamic_app_summary_cache"


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
        cache_row = runner(
            f"SELECT MAX(latest_static_run_id) FROM {STATIC_DYNAMIC_SUMMARY_CACHE}",
            fetch="one",
        )
        view_row = runner(
            f"SELECT MAX(latest_static_run_id) FROM {STATIC_DYNAMIC_SUMMARY_VIEW}",
            fetch="one",
        )
    except Exception:
        return False
    cache_max = int(cache_row[0] or 0) if cache_row else 0
    view_max = int(view_row[0] or 0) if view_row else 0
    return cache_max < view_max


def refresh_static_dynamic_summary_cache(*, reuse_connection: bool = True) -> tuple[int, datetime]:
    """Rebuild the materialized latest-package static/dynamic summary cache."""

    materialized_at = datetime.now(UTC).replace(tzinfo=None)
    inserted = 0
    with database_session(reuse_connection=reuse_connection) as db:
        db.execute(
            CREATE_WEB_STATIC_DYNAMIC_APP_SUMMARY_CACHE,
            query_name="summary_surfaces.cache.ensure_table",
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
    if count and count > 0 and not static_dynamic_summary_cache_is_stale(runner=runner):
        return STATIC_DYNAMIC_SUMMARY_CACHE
    return STATIC_DYNAMIC_SUMMARY_VIEW


__all__ = [
    "STATIC_DYNAMIC_SUMMARY_VIEW",
    "STATIC_DYNAMIC_SUMMARY_CACHE",
    "preferred_static_dynamic_summary_relation",
    "refresh_static_dynamic_summary_cache",
    "static_dynamic_summary_cache_is_stale",
    "static_dynamic_summary_cache_status",
]
