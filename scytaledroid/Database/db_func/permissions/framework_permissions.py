"""High-level helpers to persist Android framework permission metadata."""

from __future__ import annotations

from dataclasses import asdict as _asdict, is_dataclass as _is_dataclass
from typing import Iterable, Mapping, Optional

from ...db_core import run_sql
from ...db_queries.permissions import framework_permissions as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_table() -> bool:
    """Ensure the catalog table exists; returns True on success."""
    ok = table_exists()
    if not ok:
        log.warning(
            "android_framework_permissions missing; run DBA migrations.",
            category="database",
        )
    return ok


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


def catalog_fingerprint() -> str:
    """Return a stable fingerprint for the current catalog state."""

    try:
        row = run_sql(queries.SELECT_UPDATED_FINGERPRINT, fetch="one")
    except Exception:
        row = None
    if row and row[0]:
        try:
            return str(int(row[0]))
        except Exception:
            return str(row[0])
    total = count_rows() or 0
    return f"rows:{total}"


def _safe_int(value) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _coerce_str(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        # join sequences deterministically
        try:
            return "|".join(str(x) for x in value)
        except Exception:
            return str(value)
    return str(value)


def _bind_params(payload: Mapping[str, object]) -> Mapping[str, object]:
    src = dict(payload)
    # map name → perm_name
    perm_name = src.get("perm_name") or src.get("name")
    short = src.get("short")
    protection = src.get("protection")
    protection_raw = src.get("protection_raw")
    added_api = _safe_int(src.get("added_api"))
    deprecated_api = _safe_int(src.get("deprecated_api"))
    deprecated_note = _coerce_str(src.get("deprecated_note"))
    hard_restricted = 1 if src.get("hard_restricted") else 0
    soft_restricted = 1 if src.get("soft_restricted") else 0
    system_only = 1 if src.get("system_only") else 0
    constant_value = src.get("constant_value") or perm_name
    summary = _coerce_str(src.get("summary"))
    doc_url = _coerce_str(src.get("doc_url"))
    source = _coerce_str(src.get("source"))

    return {
        "perm_name": _coerce_str(perm_name),
        "short": _coerce_str(short),
        "protection": _coerce_str(protection),
        "protection_raw": _coerce_str(protection_raw),
        "added_api": added_api,
        "deprecated_api": deprecated_api,
        "deprecated_note": deprecated_note,
        "hard_restricted": int(hard_restricted),
        "soft_restricted": int(soft_restricted),
        "system_only": int(system_only),
        "constant_value": _coerce_str(constant_value),
        "summary": _coerce_str(summary),
        "doc_url": _coerce_str(doc_url),
        "source": _coerce_str(source),
    }


def upsert_permission(payload: Mapping[str, object]) -> None:
    params = _bind_params(payload)
    run_sql(queries.UPSERT_PERMISSION, params)


def upsert_permissions(items: Iterable[object], *, source: str, limit: Optional[int] = None) -> int:
    """Insert or update many permission rows; returns number processed."""
    processed = 0
    for index, meta in enumerate(items, start=1):
        if limit is not None and index > limit:
            break
        if isinstance(meta, Mapping):
            payload = dict(meta)
        elif _is_dataclass(meta):
            payload = _asdict(meta)
        else:  # best-effort attribute mapping
            payload = {k: getattr(meta, k) for k in dir(meta) if not k.startswith("_")}
        payload.setdefault("source", source)
        upsert_permission(payload)
        processed += 1
    return processed


def fetch_catalog_entries() -> list[Mapping[str, object]]:
    """Return framework catalog rows as dictionaries."""

    try:
        rows = run_sql(queries.SELECT_CATALOG, fetch="all", dictionary=True)
    except Exception:
        return []
    if not rows:
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


__all__ = [
    "ensure_table",
    "table_exists",
    "count_rows",
    "catalog_fingerprint",
    "upsert_permissions",
    "fetch_catalog_entries",
]
