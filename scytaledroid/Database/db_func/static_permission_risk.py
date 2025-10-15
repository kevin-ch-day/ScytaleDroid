"""DB helpers for per-APK permission risk persistence."""

from __future__ import annotations

from typing import Iterable, Mapping

from ..db_core import run_sql
from ..db_queries import static_permission_risk as queries


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


def upsert(payload: Mapping[str, object]) -> None:
    run_sql(queries.UPSERT_RISK, payload)


def bulk_upsert(rows: Iterable[Mapping[str, object]]) -> int:
    count = 0
    for row in rows:
        try:
            upsert(row)
            count += 1
        except Exception:
            continue
    return count


__all__ = ["ensure_table", "table_exists", "upsert", "bulk_upsert"]

