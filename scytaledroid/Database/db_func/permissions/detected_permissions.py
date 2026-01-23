"""Helpers to persist per-APK detected permissions observations."""

from __future__ import annotations

from typing import Iterable, Mapping, Optional

from ...db_core import run_sql
from ...db_queries.permissions import detected_permissions as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_table() -> bool:
    ok = table_exists()
    if not ok:
        log.warning(
            "android_detected_permissions missing; run DBA migrations.",
            category="database",
        )
    return ok


def table_exists() -> bool:
    try:
        row = run_sql(queries.TABLE_EXISTS, fetch="one")
        return bool(row and int(row[0]) > 0)
    except Exception:
        return False


def upsert_detected(payload: Mapping[str, object]) -> None:
    """Upsert detected permission row.

    Tries the apk_id-based schema first; falls back to legacy sha256-based schema
    if the new columns are not present.
    """
    try:
        run_sql(queries.UPSERT_DETECTED, payload)
    except Exception:
        # Fall back to legacy schema if available
        run_sql(queries.UPSERT_DETECTED_LEGACY, payload)


def framework_protection_map(
    names: Iterable[str],
    target_sdk: Optional[int] = None,
) -> dict[str, Optional[str]]:
    names_list = [n for n in set(names) if isinstance(n, str) and n]
    out: dict[str, Optional[str]] = {}
    if not names_list:
        return out
    # Build placeholders dynamically
    step = 100
    for i in range(0, len(names_list), step):
        chunk = names_list[i : i + step]
        placeholders = ",".join(["%s"] * len(chunk))
        sql = queries.SELECT_FRAMEWORK_PROTECTION.format(placeholders=placeholders)
        rows = run_sql(sql, tuple(chunk), fetch="all") or []
        for perm_name, protection, added_api, deprecated_api in rows:
            short = (perm_name or "").strip().upper()
            if not short:
                continue
            if target_sdk is not None:
                try:
                    added = int(added_api) if added_api is not None else None
                except (TypeError, ValueError):
                    added = None
                try:
                    deprecated = int(deprecated_api) if deprecated_api is not None else None
                except (TypeError, ValueError):
                    deprecated = None
                if added is not None and target_sdk < added:
                    continue
                if deprecated is not None and target_sdk >= deprecated:
                    pass
            out[short] = str(protection) if protection is not None else None
    return out


__all__ = [
    "ensure_table",
    "table_exists",
    "upsert_detected",
    "framework_protection_map",
]
