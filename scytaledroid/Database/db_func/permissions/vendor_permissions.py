"""Helpers to persist vendor/custom Android permissions."""

from __future__ import annotations

from typing import Mapping, Optional

from ...db_core import run_sql
from ...db_queries.permissions import vendor_permissions as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_table() -> bool:
    log.warning(
        "android_vendor_permissions is deprecated; use android_permission_dict_oem.",
        category="database",
    )
    return False


def table_exists() -> bool:
    return False


def upsert_vendor_permission(payload: Mapping[str, object]) -> None:
    log.warning(
        "vendor permission upsert ignored (deprecated).",
        category="database",
    )


__all__ = [
    "ensure_table",
    "table_exists",
    "upsert_vendor_permission",
]
