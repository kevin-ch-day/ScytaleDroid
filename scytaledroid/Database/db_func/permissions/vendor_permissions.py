"""Helpers to persist vendor/custom Android permissions."""

from __future__ import annotations

from typing import Mapping, Optional

from ...db_core import run_sql
from ...db_queries.permissions import vendor_permissions as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_table() -> bool:
    ok = table_exists()
    if not ok:
        log.warning(
            "android_vendor_permissions missing; run DBA migrations.",
            category="database",
        )
    return ok


def table_exists() -> bool:
    try:
        row = run_sql(queries.TABLE_EXISTS, fetch="one")
        return bool(row and int(row[0]) > 0)
    except Exception:
        return False


def upsert_vendor_permission(payload: Mapping[str, object]) -> None:
    params = dict(payload)
    # Remove legacy fields if present in the payload
    params.pop("occurrences", None)
    params.pop("first_seen_apk", None)
    run_sql(queries.UPSERT_VENDOR, params)


__all__ = [
    "ensure_table",
    "table_exists",
    "upsert_vendor_permission",
]
