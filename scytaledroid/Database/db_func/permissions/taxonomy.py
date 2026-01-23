"""Helpers for the permission taxonomy scaffolding tables."""

from __future__ import annotations

from typing import Mapping

from ...db_core import db_config, run_sql
from ...db_queries.permissions import taxonomy as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_tables() -> bool:
    """Ensure taxonomy tables exist. Returns True if all statements succeed."""
    engine = str(db_config.DB_CONFIG.get("engine", "sqlite")).lower()
    if engine != "sqlite" and not db_config.allow_auto_create():
        ok = True
        for name in ("perm_groups", "android_perm_map", "android_perm_override"):
            row = run_sql(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
                (name,),
                fetch="one",
            )
            present = bool(row and int(row[0]) > 0)
            ok = ok and present
            if not present:
                log.warning(
                    f"{name} missing; run bootstrap or migrations.",
                    category="database",
                )
        return ok
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
