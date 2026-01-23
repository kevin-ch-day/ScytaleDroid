"""Helpers to persist unknown/suspicious Android permissions."""

from __future__ import annotations

from typing import Mapping

from ...db_core import run_sql
from ...db_queries.permissions import unknown_permissions as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_table() -> bool:
    ok = table_exists()
    if not ok:
        log.warning(
            "android_unknown_permissions missing; run DBA migrations.",
            category="database",
        )
    return ok


def table_exists() -> bool:
    try:
        row = run_sql(queries.TABLE_EXISTS, fetch="one")
        return bool(row and int(row[0]) > 0)
    except Exception:
        return False


def upsert_unknown_permission(payload: Mapping[str, object]) -> None:
    params = dict(payload)
    # Remove legacy fields if present in the payload
    params.pop("observed_in_pkg", None)
    params.pop("observed_in_sha256", None)
    params.pop("occurrences", None)
    run_sql(queries.UPSERT_UNKNOWN, params)


def mark_ghost_aosp(perm_name: str, baseline_version: str) -> None:
    if not perm_name:
        return
    try:
        run_sql(
            queries.UPDATE_GHOST,
            {"perm_name": perm_name, "ghost_baseline_version": baseline_version},
        )
    except Exception as exc:
        log.warning(
            f"Failed to update GhostAOSP flag for {perm_name}: {exc}",
            category="database",
        )


__all__ = [
    "ensure_table",
    "table_exists",
    "upsert_unknown_permission",
    "mark_ghost_aosp",
]
