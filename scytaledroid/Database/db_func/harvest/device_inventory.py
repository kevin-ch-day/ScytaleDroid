"""Helpers to persist device inventory snapshots and package rows."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...db_core import run_sql, run_sql_many
from ...db_queries.harvest import device_inventory as queries
from ...db_utils.package_utils import is_suspicious_package_name, normalize_package_name

_TABLES_READY = False


def ensure_tables() -> bool:
    """Ensure the device inventory tables exist."""
    global _TABLES_READY
    if _TABLES_READY:
        return True
    try:
        row = run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
            ("device_inventory_snapshots",),
            fetch="one",
        )
        ok_snap = bool(row and int(row[0]) > 0)
        row = run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
            ("device_inventory",),
            fetch="one",
        )
        ok_inv = bool(row and int(row[0]) > 0)
        if not (ok_snap and ok_inv):
            log.warning(
                "device_inventory tables missing; load a DB snapshot or apply migrations.",
                category="database",
            )
        _TABLES_READY = ok_snap and ok_inv
        return _TABLES_READY
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(f"Failed to check inventory tables: {exc}", category="database")
        return False


def create_snapshot(
    device_serial: str,
    *,
    captured_at: datetime,
    package_count: int,
    duration_seconds: float | None,
    package_hash: str | None,
    package_list_hash: str | None,
    package_signature_hash: str | None,
    build_fingerprint: str | None,
    scope_hash: str | None,
    snapshot_type: str | None,
    scope_variant: str | None,
    scope_size: int | None,
    extras: Mapping[str, object] | None = None,
) -> int | None:
    """Insert a snapshot header and return its snapshot_id."""

    if not ensure_tables():
        return None

    captured_naive = captured_at.replace(tzinfo=None) if captured_at.tzinfo else captured_at
    extras_payload: str | None
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
    *,
    batch_size: int = 200,
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

    rows = []
    for entry in packages:
        bound = _bind_package(snapshot_id, device_serial, entry)
        if bound is None:
            continue
        rows.append(bound)

    if not rows:
        log.warning(
            "No inventory rows available after binding; refusing to persist empty snapshot.",
            category="database",
            extra={"snapshot_id": snapshot_id, "device_serial": device_serial},
        )
        return 0

    try:
        inserted = 0
        for batch_start in range(0, len(rows), batch_size):
            batch = rows[batch_start : batch_start + batch_size]
            run_sql_many(queries.INSERT_PACKAGE, batch)
            inserted += len(batch)
            log.info(
                f"Persisted inventory rows {inserted}/{len(rows)} for snapshot {snapshot_id}.",
                category="database",
            )
        return inserted
    except Exception as exc:  # pragma: no cover - defensive
        sample = rows[0] if rows else None
        log.warning(
            f"Failed to persist inventory rows: {exc}",
            category="database",
            extra={"rows": len(rows), "sample": sample},
        )
        return 0


def _bind_package(
    snapshot_id: int,
    device_serial: str,
    entry: Mapping[str, object],
) -> tuple[object, ...] | None:
    """Coerce a package entry into the SQL parameter tuple."""

    def _text(value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _int(value: object) -> int | None:
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

    raw_package = _text(entry.get("package_name"))
    if not raw_package:
        return None
    cleaned_package = normalize_package_name(raw_package, context="database")
    if not cleaned_package:
        return None
    suspicious = is_suspicious_package_name(cleaned_package)
    if suspicious:
        review_needed = 1
        log.warning(
            f"Suspicious package_name '{raw_package}' in inventory snapshot; persisting with review flag.",
            category="database",
        )

    return (
        snapshot_id,
        device_serial,
        cleaned_package,
        _text(entry.get("app_label")),
        _text(entry.get("version_name")),
        _text(entry.get("version_code")),
        _text(entry.get("installer")),
        _text(entry.get("category_name") or entry.get("category")),
        _int(entry.get("category_id")),
        inferred_category,
        _text(entry.get("source")),
        _text(entry.get("partition")),
        _text(entry.get("profile_key") or entry.get("profile_id")),
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
        _serialise_json(
            _merge_extras(
                extras,
                raw_package=raw_package,
                cleaned_package=cleaned_package,
                suspicious=suspicious,
            )
        ),
    )


def _serialise_json(value: object) -> str | None:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return None


def _prepare_extras(entry: Mapping[str, object]) -> dict | None:
    """Return lightweight auxiliary fields that lack dedicated columns."""
    extras = {}
    if "category" in entry and entry.get("category") != entry.get("category_name"):
        extras["category"] = entry.get("category")
    if entry.get("publisher_key"):
        extras["publisher_key"] = entry.get("publisher_key")
    if entry.get("publisher_name"):
        extras["publisher_name"] = entry.get("publisher_name")
    if entry.get("category_source"):
        extras["category_source"] = entry.get("category_source")
    if entry.get("profile_source"):
        extras["profile_source"] = entry.get("profile_source")
    if entry.get("publisher_source"):
        extras["publisher_source"] = entry.get("publisher_source")
    if "split_flag" in entry:
        extras["split_flag"] = entry.get("split_flag")
    return extras or None


def _merge_extras(
    extras: dict | None,
    *,
    raw_package: str,
    cleaned_package: str,
    suspicious: bool,
) -> dict | None:
    merged = dict(extras or {})
    if raw_package != cleaned_package:
        merged.setdefault("raw_package_name", raw_package)
        merged.setdefault("normalized_package_name", cleaned_package)
    if suspicious:
        merged.setdefault("review_needed_reason", "suspicious_package_name")
        merged.setdefault("suspicious_flags", ["package_name"])
    return merged or None


__all__ = [
    "ensure_tables",
    "create_snapshot",
    "replace_packages",
]
