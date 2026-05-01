"""Shared DB verification helpers for static analysis runs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from scytaledroid.Database.db_core import db_queries as core_q

from .static_run_map import extract_static_run_ids, load_run_map


def table_has_column(table: str, column: str) -> bool:
    """Return True when a DB table contains a column."""
    try:
        row = core_q.run_sql(
            f"SHOW COLUMNS FROM {table} LIKE %s",
            (column,),
            fetch="one",
        )
    except Exception:
        return False
    return bool(row)


def resolve_static_run_ids(session_stamp: str) -> list[int]:
    """Resolve static run ids for a session from run_map first, then DB fallback."""
    try:
        run_map = load_run_map(session_stamp)
    except Exception:
        run_map = None

    try:
        static_ids = extract_static_run_ids(run_map) if isinstance(run_map, Mapping) else []
    except Exception:
        static_ids = []

    if static_ids:
        return static_ids

    try:
        rows = core_q.run_sql(
            """
            SELECT id
            FROM static_analysis_runs
            WHERE session_stamp = %s
            ORDER BY id DESC
            """,
            (session_stamp,),
            fetch="all",
        )
    except Exception:
        return []

    return [int(row[0]) for row in rows or [] if row and row[0] is not None]


def placeholders_for(values: Sequence[object]) -> str:
    """Return a %s placeholder list for SQL IN clauses."""
    return ",".join(["%s"] * len(values))