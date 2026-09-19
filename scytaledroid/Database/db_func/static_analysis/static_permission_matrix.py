"""Database helpers for static_permission_matrix persistence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...db_core import run_sql, run_sql_many
from ...db_queries.static_analysis import static_permission_matrix as queries

_MATRIX_TABLE_READY = False


def ensure_table() -> bool:
    """Verify ``static_permission_matrix`` exists."""
    global _MATRIX_TABLE_READY
    if _MATRIX_TABLE_READY:
        return True
    ok = table_exists()
    if not ok:
        log.warning(
            "static_permission_matrix missing; apply migrations.",
            category="database",
        )
        return False
    _MATRIX_TABLE_READY = True
    return True


def table_exists() -> bool:
    """Return ``True`` when the matrix table is available."""
    try:
        row = run_sql(queries.TABLE_EXISTS, fetch="one")
    except Exception:
        return False
    return bool(row and int(row[0]) > 0)


def replace_for_run(run_id: int, rows: Iterable[Mapping[str, object]]) -> int:
    """Replace matrix entries for ``run_id`` with ``rows``."""
    run_sql(queries.DELETE_FOR_RUN, (run_id,))
    payloads = [tuple(row.get(key) for key in queries.INSERT_ROW_KEYS) for row in rows]
    if not payloads:
        return 0
    run_sql_many(queries.INSERT_ROWS_MANY, payloads)
    return len(payloads)


__all__ = ["ensure_table", "table_exists", "replace_for_run"]
