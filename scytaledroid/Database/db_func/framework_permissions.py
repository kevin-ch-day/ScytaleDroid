"""High-level helpers to persist Android framework permission metadata."""

from __future__ import annotations

from typing import Iterable, Mapping, Optional

from ..db_core import run_sql
from ..db_queries import framework_permissions as queries


def ensure_table() -> bool:
    """Ensure the catalog table exists; returns True on success."""

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


def count_rows() -> Optional[int]:
    try:
        row = run_sql(queries.COUNT_ROWS, fetch="one")
        return int(row[0]) if row else 0
    except Exception:
        return None


def upsert_permission(payload: Mapping[str, object]) -> None:
    # Adapt payload to schema (perm_name column)
    params = dict(payload)
    if "perm_name" not in params and "name" in params:
        params["perm_name"] = params.get("name")
    if params.get("constant_value") is None and params.get("perm_name"):
        params["constant_value"] = params["perm_name"]
    run_sql(queries.UPSERT_PERMISSION, params)


def upsert_permissions(items: Iterable[Mapping[str, object]], *, source: str, limit: Optional[int] = None) -> int:
    """Insert or update many permission rows; returns number processed."""
    processed = 0
    for index, meta in enumerate(items, start=1):
        if limit is not None and index > limit:
            break
        payload = dict(meta)
        payload.setdefault("source", source)
        payload["hard_restricted"] = 1 if payload.get("hard_restricted") else 0
        payload["soft_restricted"] = 1 if payload.get("soft_restricted") else 0
        payload["system_only"] = 1 if payload.get("system_only") else 0
        upsert_permission(payload)
        processed += 1
    return processed


__all__ = [
    "ensure_table",
    "table_exists",
    "count_rows",
    "upsert_permissions",
]
