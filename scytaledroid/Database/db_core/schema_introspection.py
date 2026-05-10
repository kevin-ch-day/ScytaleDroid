"""Shared DATABASE() probes against ``information_schema`` (operational schema only)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from scytaledroid.Database.db_core.db_queries import run_sql

_TABLE_EXISTS_SQL = """
SELECT COUNT(*)
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name = %s
"""


def table_exists(
    table_name: str,
    *,
    query_name: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> bool:
    """True when the active schema has any ``information_schema.tables`` row for *table_name*."""
    try:
        row = run_sql(
            _TABLE_EXISTS_SQL,
            (table_name,),
            fetch="one",
            query_name=query_name,
            context=context,
        )
        return bool(row and int(row[0] or 0) > 0)
    except Exception:
        return False


__all__ = ["table_exists"]
