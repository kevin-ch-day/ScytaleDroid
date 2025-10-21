"""Helpers for the permission taxonomy scaffolding tables."""

from __future__ import annotations

from typing import Mapping

from ...db_core import run_sql
from ...db_queries.permissions import taxonomy as queries


def ensure_tables() -> bool:
    """Ensure taxonomy tables exist. Returns True if all statements succeed."""

    try:
        run_sql(queries.CREATE_GROUPS)
        run_sql(queries.CREATE_ANDROID_PERM_MAP)
        run_sql(queries.CREATE_ANDROID_PERM_OVERRIDE)
        return True
    except Exception:
        return False


def fetch_groups() -> list[Mapping[str, object]]:
    try:
        rows = run_sql(queries.SELECT_GROUPS, fetch="all", dictionary=True)
    except Exception:
        return []
    if not rows:
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def fetch_permission_map() -> list[Mapping[str, object]]:
    try:
        rows = run_sql(queries.SELECT_PERMISSION_MAP, fetch="all", dictionary=True)
    except Exception:
        return []
    if not rows:
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def fetch_package_overrides(package_name: str) -> list[Mapping[str, object]]:
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

