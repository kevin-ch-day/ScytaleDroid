"""Shared session uniqueness checks for static entrypoints."""

from __future__ import annotations

from scytaledroid.Utils.LoggingUtils import logging_utils as log

try:  # optional during offline runs
    from scytaledroid.Database.db_core import db_queries as core_q
except Exception:  # pragma: no cover - offline mode
    core_q = None


def check_session_uniqueness(
    session_stamp: str | None,
    package_name: str,
    allow_reuse: bool,
    *,
    dry_run: bool = False,
) -> None:
    if allow_reuse or dry_run or not session_stamp or core_q is None:
        return
    try:
        rows = core_q.run_sql(
            """
            SELECT sar.id
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.session_stamp = %s
              AND a.package_name = %s
            """,
            (session_stamp, package_name),
            fetch="all",
        )
        if rows:
            raise SystemExit(
                f"Session '{session_stamp}' for package '{package_name}' already exists "
                "(static_analysis_runs). Use a new --session or --allow-session-reuse explicitly."
            )
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - DB optional
        log.warning(f"Session uniqueness check failed (skipping): {exc}", category="static")


__all__ = ["check_session_uniqueness"]
