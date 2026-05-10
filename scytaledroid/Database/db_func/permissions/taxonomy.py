"""Helpers for the permission taxonomy scaffolding tables."""

from __future__ import annotations

from collections.abc import Mapping

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...db_core import run_sql
from ...db_core.schema_introspection import table_exists
from ...db_queries.permissions import taxonomy as queries


def ensure_tables() -> bool:
    """Ensure taxonomy tables exist. Legacy map/override tables are deprecated."""
    ok = True
    name = "perm_groups"
    present = table_exists(name)
    ok = ok and present
    if not present:
        log.warning(
            f"{name} missing; run DBA migrations.",
            category="database",
        )
    return ok


def fetch_groups() -> list[Mapping[str, object]]:
    try:
        rows = run_sql(queries.SELECT_GROUPS, fetch="all", dictionary=True)
    except Exception:
        return []
    if not rows:
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def fetch_permission_map() -> list[Mapping[str, object]]:
    if queries.SELECT_PERMISSION_MAP.strip().upper() == "SELECT 0":
        return []
    try:
        rows = run_sql(queries.SELECT_PERMISSION_MAP, fetch="all", dictionary=True)
    except Exception:
        return []
    if not rows:
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def fetch_package_overrides(package_name: str) -> list[Mapping[str, object]]:
    if queries.SELECT_PACKAGE_OVERRIDES.strip().upper() == "SELECT 0":
        return []
    try:
        rows = run_sql(
            queries.SELECT_PACKAGE_OVERRIDES,
            (package_name,),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return []
    if not rows:
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


__all__ = [
    "ensure_tables",
    "fetch_groups",
    "fetch_permission_map",
    "fetch_package_overrides",
]
