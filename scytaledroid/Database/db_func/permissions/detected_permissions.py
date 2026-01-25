"""Helpers to persist per-APK detected permissions observations."""

from __future__ import annotations

from typing import Iterable, Mapping, Optional

from ...db_core import run_sql
from ...db_queries.permissions import detected_permissions as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_table() -> bool:
    log.warning(
        "android_detected_permissions is deprecated; use permission dict tables.",
        category="database",
    )
    return False


def table_exists() -> bool:
    return False


def upsert_detected(payload: Mapping[str, object]) -> None:
    log.warning(
        "detected permission upsert ignored (deprecated).",
        category="database",
    )


def framework_protection_map(
    names: Iterable[str],
    target_sdk: Optional[int] = None,
) -> dict[str, Optional[str]]:
    return {}


__all__ = [
    "ensure_table",
    "table_exists",
    "upsert_detected",
    "framework_protection_map",
]
