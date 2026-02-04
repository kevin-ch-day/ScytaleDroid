"""Query helpers for health checks."""

from __future__ import annotations

from typing import Any


def fetch_latest_run(run_sql) -> dict[str, Any] | None:
    try:
        return run_sql(
            "SELECT run_id, package, version_name, target_sdk, ts, session_stamp FROM runs ORDER BY run_id DESC LIMIT 1",
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None


def fetch_latest_session(run_sql) -> dict[str, Any] | None:
    try:
        return run_sql(
            """
            SELECT session_stamp, package_name
            FROM static_findings_summary
            ORDER BY created_at DESC
            LIMIT 1
            """,
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None
