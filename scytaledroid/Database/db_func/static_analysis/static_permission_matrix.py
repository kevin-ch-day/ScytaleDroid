"""Database helpers for static_permission_matrix persistence."""

from __future__ import annotations

from typing import Iterable, Mapping

from ...db_core import run_sql
from ...db_queries.static_analysis import static_permission_matrix as queries


def ensure_table() -> bool:
    """Ensure ``static_permission_matrix`` exists."""
    try:
        run_sql(queries.CREATE_TABLE)
        return True
    except Exception:
        return False


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
    count = 0
    for row in rows:
        run_sql(queries.INSERT_ROWS, row)
        count += 1
    return count


__all__ = ["ensure_table", "table_exists", "replace_for_run"]
