"""Helpers to persist unknown/suspicious Android permissions."""

from __future__ import annotations

from typing import Mapping

from ...db_core import run_sql
from ...db_queries.permissions import unknown_permissions as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_table() -> bool:
    log.warning(
        "android_unknown_permissions is deprecated; use android_permission_dict_unknown.",
        category="database",
    )
    return False


def table_exists() -> bool:
    return False


def upsert_unknown_permission(payload: Mapping[str, object]) -> None:
    log.warning(
        "unknown permission upsert ignored (deprecated).",
        category="database",
    )


def mark_ghost_aosp(perm_name: str, baseline_version: str) -> None:
    if perm_name:
        log.warning(
            "ghost AOSP updates are deprecated; use dict triage_status instead.",
            category="database",
        )


__all__ = [
    "ensure_table",
    "table_exists",
    "upsert_unknown_permission",
    "mark_ghost_aosp",
]
