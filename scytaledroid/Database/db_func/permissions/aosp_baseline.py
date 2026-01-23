"""Helpers for AOSP permission baseline lookups."""

from __future__ import annotations

from functools import lru_cache
from typing import Iterable, Optional

from ...db_core import db_config, run_sql
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def _auto_create_allowed() -> bool:
    engine = str(db_config.DB_CONFIG.get("engine", "sqlite")).lower()
    return engine == "sqlite" or db_config.allow_auto_create()


def baseline_exists(android_release: str) -> bool:
    try:
        row = run_sql(
            "SELECT COUNT(*) FROM aosp_permission_baseline WHERE android_release = %s",
            (android_release,),
            fetch="one",
        )
        return bool(row and int(row[0]) > 0)
    except Exception:
        return False


@lru_cache(maxsize=16)
def fetch_permissions(android_release: str) -> set[str]:
    try:
        rows = run_sql(
            """
            SELECT permission_string
            FROM aosp_permission_baseline
            WHERE android_release = %s
            """,
            (android_release,),
            fetch="all",
        )
        return {str(row[0]).strip() for row in rows or [] if row and row[0]}
    except Exception as exc:
        log.warning(
            f"AOSP baseline lookup failed for {android_release}: {exc}",
            category="database",
        )
        return set()


def permission_in_baseline(permission: str, android_release: str) -> bool:
    if not permission or not android_release:
        return False
    perms = fetch_permissions(android_release)
    return permission in perms


__all__ = [
    "baseline_exists",
    "fetch_permissions",
    "permission_in_baseline",
]
