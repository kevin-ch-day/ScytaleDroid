"""Query helpers for health checks."""

from __future__ import annotations

from typing import Any


def fetch_latest_run(run_sql) -> dict[str, Any] | None:
    try:
        return run_sql(
            """
            SELECT
              sar.id AS static_run_id,
              legacy.legacy_run_id,
              a.package_name AS package_name,
              av.version_name,
              av.version_code,
              av.target_sdk AS target_sdk,
              sar.created_at,
              sar.status,
              sar.session_stamp
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            LEFT JOIN (
              SELECT session_stamp, MAX(run_id) AS legacy_run_id
              FROM runs
              GROUP BY session_stamp
            ) AS legacy
              ON legacy.session_stamp = sar.session_stamp
            ORDER BY sar.id DESC
            LIMIT 1
            """,
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None


def fetch_latest_session(run_sql) -> dict[str, Any] | None:
    try:
        return run_sql(
            """
            SELECT
              sar.session_stamp,
              a.package_name,
              sar.id AS static_run_id,
              sar.created_at
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            ORDER BY sar.id DESC
            LIMIT 1
            """,
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None
