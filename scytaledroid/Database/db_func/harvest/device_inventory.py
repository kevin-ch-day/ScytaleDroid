"""Helpers to persist device inventory snapshots and package rows."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Mapping, Optional, Sequence

from ...db_core import run_sql, run_sql_many
from ...db_queries.harvest import device_inventory as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log


_TABLES_READY = False


def ensure_tables() -> bool:
    """Ensure the device inventory tables exist."""
    global _TABLES_READY
    if _TABLES_READY:
        return True
    try:
        run_sql(queries.CREATE_SNAPSHOTS_TABLE)
        run_sql(queries.CREATE_INVENTORY_TABLE)
        _TABLES_READY = True
        return True
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(f"Failed to ensure inventory tables: {exc}", category="database")
        return False


def create_snapshot(
    device_serial: str,
    *,
    captured_at: datetime,
    package_count: int,
    duration_seconds: Optional[float],
    package_hash: Optional[str],
    package_list_hash: Optional[str],
    package_signature_hash: Optional[str],
    build_fingerprint: Optional[str],
    scope_hash: Optional[str],
    snapshot_type: Optional[str],
    scope_variant: Optional[str],
    scope_size: Optional[int],
    extras: Optional[Mapping[str, object]] = None,
) -> Optional[int]:
    """Insert a snapshot header and return its snapshot_id."""

    if not ensure_tables():
        return None

    captured_naive = captured_at.replace(tzinfo=None) if captured_at.tzinfo else captured_at
    extras_payload: Optional[str]
    if extras:
        try:
            extras_payload = json.dumps(extras, ensure_ascii=False, sort_keys=True)
        except TypeError:
            extras_payload = None
    else:
        extras_payload = None

    params = (
        device_serial,
        captured_naive,
        int(package_count),
        float(duration_seconds) if duration_seconds is not None else None,
        package_hash,
        package_list_hash,
        package_signature_hash,
        build_fingerprint,
        scope_hash,
        snapshot_type,
        scope_variant,
        int(scope_size) if scope_size is not None else None,
        extras_payload,
    )

    try:
        snapshot_id = run_sql(
            queries.INSERT_SNAPSHOT,
            params,
            return_lastrowid=True,
        )
        return int(snapshot_id) if snapshot_id is not None else None
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(f"Failed to insert inventory snapshot: {exc}", category="database")
        return None


def replace_packages(
    snapshot_id: int,
    device_serial: str,
    packages: Sequence[Mapping[str, object]],
) -> int:
    """Replace package rows for *snapshot_id* with *packages*."""

    if not packages:
        return 0

    try:
        run_sql(queries.DELETE_PACKAGES_FOR_SNAPSHOT, (snapshot_id,))
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed clearing inventory rows for snapshot {snapshot_id}: {exc}",
            category="database",
        )
        # Continue attempting inserts despite the warning.

    rows = [_bind_package(snapshot_id, device_serial, entry) for entry in packages]
    try:
        run_sql_many(queries.INSERT_PACKAGE, rows)
        return len(rows)
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(f"Failed to persist inventory rows: {exc}", category="database")
        return 0


def _bind_package(
    snapshot_id: int,
    device_serial: str,
    entry: Mapping[str, object],
) -> tuple[object, ...]:
    """Coerce a package entry into the SQL parameter tuple."""

    def _text(value: object) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _int(value: object) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    split_count = _int(entry.get("split_count")) or 1
    is_split = 1 if split_count > 1 else 0

    inferred_category = 1 if bool(entry.get("inferred_category")) else 0
    inferred_profile = 1 if bool(entry.get("inferred_profile")) else 0
    review_needed = 1 if bool(entry.get("review_needed")) else 0

    apk_dirs = _serialise_json(entry.get("apk_dirs"))
    apk_paths = _serialise_json(entry.get("apk_paths"))

    extras = _prepare_extras(entry)
    extras_payload = _serialise_json(extras)

    return (
        snapshot_id,
        device_serial,
        _text(entry.get("package_name")),
        _text(entry.get("app_label")),
        _text(entry.get("version_name")),
        _text(entry.get("version_code")),
        _text(entry.get("installer")),
        _text(entry.get("category_name") or entry.get("category")),
        _int(entry.get("category_id")),
        inferred_category,
        _text(entry.get("source")),
        _text(entry.get("partition")),
        _text(entry.get("profile_id")),
        _text(entry.get("profile_name")),
        inferred_profile,
        split_count,
        is_split,
        review_needed,
        _text(entry.get("first_install")),
        _text(entry.get("last_update")),
        _text(entry.get("primary_path")),
        apk_dirs,
        apk_paths,
        extras_payload,
    )


def _serialise_json(value: object) -> Optional[str]:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return None


def _prepare_extras(entry: Mapping[str, object]) -> Optional[dict]:
    """Return lightweight auxiliary fields that lack dedicated columns."""
    extras = {}
    if "category" in entry and entry.get("category") != entry.get("category_name"):
        extras["category"] = entry.get("category")
    if "split_flag" in entry:
        extras["split_flag"] = entry.get("split_flag")
    return extras or None


__all__ = [
    "ensure_tables",
    "create_snapshot",
    "replace_packages",
]
