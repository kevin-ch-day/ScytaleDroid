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
    log.warning(
        "AOSP baseline table is deprecated; use android_permission_dict_aosp.",
        category="database",
    )
    return False


@lru_cache(maxsize=16)
def fetch_permissions(android_release: str) -> set[str]:
    log.warning(
        "AOSP baseline fetch ignored (deprecated).",
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
