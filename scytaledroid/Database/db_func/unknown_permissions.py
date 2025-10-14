"""Helpers to persist unknown/suspicious Android permissions."""

from __future__ import annotations

from typing import Mapping

from ..db_core import run_sql
from ..db_queries import unknown_permissions as queries


def ensure_table() -> bool:
    try:
        run_sql(queries.CREATE_TABLE)
        return True
    except Exception:
        return False


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


__all__ = [
    "ensure_table",
    "table_exists",
    "upsert_unknown_permission",
]
