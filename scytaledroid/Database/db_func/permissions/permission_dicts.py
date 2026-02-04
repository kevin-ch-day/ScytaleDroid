"""DB helpers for permission dictionary + vendor metadata tables."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from ...db_core import run_sql
from ...db_queries.permissions import permission_dicts as queries


@dataclass(frozen=True)
class VendorHint:
    vendor_id: int
    vendor_name: str
    vendor_slug: str


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


def fetch_aosp_entries(values: Iterable[str], *, case_insensitive: bool = False) -> dict[str, Mapping[str, object]]:
    items = [v for v in set(values) if isinstance(v, str) and v]
    if not items:
        return {}
    placeholders = ",".join(["%s"] * len(items))
    if case_insensitive:
        sql = queries.SELECT_AOSP_BY_VALUE_LOWER.format(placeholders=placeholders)
        rows = run_sql(sql, tuple(v.lower() for v in items), fetch="all") or []
    else:
        sql = queries.SELECT_AOSP_BY_VALUE.format(placeholders=placeholders)
        rows = run_sql(sql, tuple(items), fetch="all") or []
    out: dict[str, Mapping[str, object]] = {}
    for row in rows:
        if not row:
            continue
        constant_value = str(row[0] or "").strip()
        if not constant_value:
            continue
        out[constant_value] = {
            "constant_value": constant_value,
            "name": row[1],
            "protection_level": row[2],
            "hard_restricted": row[3],
            "soft_restricted": row[4],
            "not_for_third_party_apps": row[5],
            "is_deprecated": row[6],
            "added_in_api_level": row[7],
            "deprecated_in_api_level": row[8],
        }
    return out


def fetch_aosp_protection_map(short_names: Iterable[str], target_sdk: int | None = None) -> dict[str, str | None]:
    names = [n for n in set(short_names) if isinstance(n, str) and n]
    if not names:
        return {}
    placeholders = ",".join(["%s"] * len(names))
    sql = queries.SELECT_AOSP_BY_NAME.format(placeholders=placeholders)
    rows = run_sql(sql, tuple(names), fetch="all") or []
    out: dict[str, str | None] = {}
    for row in rows:
        if not row:
            continue
        name = str(row[0] or "").strip().upper()
        if not name:
            continue
        added = row[6]
        deprecated = row[7]
        if target_sdk is not None:
            try:
                added_int = int(added) if added is not None else None
            except (TypeError, ValueError):
                added_int = None
            try:
                deprecated_int = int(deprecated) if deprecated is not None else None
            except (TypeError, ValueError):
                deprecated_int = None
            if added_int is not None and target_sdk < added_int:
                continue
            if deprecated_int is not None and target_sdk >= deprecated_int:
                pass
        out[name] = str(row[1]) if row[1] is not None else None
    return out


def fetch_oem_entries(values: Iterable[str]) -> dict[str, Mapping[str, object]]:
    items = [v for v in set(values) if isinstance(v, str) and v]
    if not items:
        return {}
    placeholders = ",".join(["%s"] * len(items))
    sql = queries.SELECT_OEM_BY_VALUE.format(placeholders=placeholders)
    rows = run_sql(sql, tuple(items), fetch="all") or []
    out: dict[str, Mapping[str, object]] = {}
    for row in rows:
        if not row:
            continue
        perm = str(row[0] or "").strip()
        if not perm:
            continue
        out[perm] = {
            "permission_string": perm,
            "vendor_id": row[1],
            "display_name": row[2],
            "protection_level": row[3],
            "confidence": row[4],
            "classification_source": row[5],
        }
    return out


def fetch_vendor_prefix_rules() -> list[Mapping[str, object]]:
    rows = run_sql(queries.SELECT_VENDOR_PREFIX_RULES, fetch="all") or []
    return [
        {"vendor_id": row[0], "namespace_prefix": row[1], "match_type": row[2]}
        for row in rows
        if row
    ]


def fetch_vendor_meta() -> dict[int, VendorHint]:
    rows = run_sql(queries.SELECT_VENDOR_META, fetch="all") or []
    out: dict[int, VendorHint] = {}
    for row in rows:
        if not row or row[0] is None:
            continue
        vendor_id = int(row[0])
        out[vendor_id] = VendorHint(
            vendor_id=vendor_id,
            vendor_name=str(row[1] or ""),
            vendor_slug=str(row[2] or ""),
        )
    return out


def upsert_unknown(payload: Mapping[str, object]) -> None:
    params = dict(payload)
    params.setdefault("first_seen_at_utc", _utc_now())
    params.setdefault("last_seen_at_utc", params["first_seen_at_utc"])
    params.setdefault("seen_count", 1)
    run_sql(queries.UPSERT_UNKNOWN, params)


def insert_queue(payload: Mapping[str, object]) -> None:
    params = dict(payload)
    now = _utc_now()
    params.setdefault("created_at_utc", now)
    params.setdefault("updated_at_utc", now)
    params.setdefault("status", "queued")
    run_sql(queries.INSERT_QUEUE, params)


def update_oem_seen(permission_string: str) -> None:
    if not permission_string:
        return
    run_sql(
        queries.UPDATE_OEM_SEEN,
        {"permission_string": permission_string, "last_seen_at_utc": _utc_now()},
    )


__all__ = [
    "VendorHint",
    "fetch_aosp_entries",
    "fetch_aosp_protection_map",
    "fetch_oem_entries",
    "fetch_vendor_prefix_rules",
    "fetch_vendor_meta",
    "upsert_unknown",
    "insert_queue",
    "update_oem_seen",
]
