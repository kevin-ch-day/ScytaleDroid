"""Helpers for the permission taxonomy scaffolding tables."""

from __future__ import annotations

from collections.abc import Mapping

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...db_core import run_sql
from ...db_core.schema_introspection import table_exists
from ...db_queries.permissions import taxonomy as queries


def ensure_tables() -> bool:
    """Return True when the ``perm_groups`` table is present."""
    name = "perm_groups"
    present = table_exists(name)
    if not present:
        log.warning(
            f"{name} missing; run DBA migrations.",
            category="database",
        )
    return present


def fetch_groups() -> list[Mapping[str, object]]:
    try:
        rows = run_sql(queries.SELECT_GROUPS, fetch="all", dictionary=True)
    except Exception:
        return []
    if not rows:
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


__all__ = [
    "ensure_tables",
    "fetch_groups",
]
