"""Snapshot I/O helpers for inventory (UI-free)."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis import inventory_meta
from scytaledroid.Utils.LoggingUtils import logging_utils as log

if TYPE_CHECKING:  # pragma: no cover
    pass
from scytaledroid.Database.db_core import database_session, run_sql
from scytaledroid.Database.db_func.harvest import device_inventory as inventory_repo
from scytaledroid.Database.db_utils.package_utils import normalize_package_name

_STATE_ROOT = Path(app_config.DATA_DIR) / app_config.DEVICE_STATE_DIR
_INVENTORY_RETENTION_N = 5


def _prune_inventory_files(serial: str, *, keep_last: int) -> tuple[int, int]:
    """Prune inventory history files under data/state/<serial>/inventory.

    Keep latest pointers; prune only inventory_<timestamp>* history files.
    Returns (before_count, deleted_count) for history files.
    """
    inv_dir = _STATE_ROOT / serial / "inventory"
    if not inv_dir.exists():
        return 0, 0

    def _timestamp_from_name(name: str) -> str | None:
        # inventory_YYYYMMDD-HHMMSS[.<variant>].json
        # inventory_YYYYMMDD-HHMMSS[.<variant>].meta.json
        if not name.startswith("inventory_"):
            return None
        # Extract the first timestamp token after inventory_
        rest = name[len("inventory_") :]
        ts = rest.split(".", 1)[0]
        if len(ts) != 15 or "-" not in ts:
            return None
        return ts

    history_files: list[Path] = []
    for path in inv_dir.iterdir():
        if not path.is_file():
            continue
        name = path.name
        if not name.startswith("inventory_"):
            continue
        if not (name.endswith(".json") or name.endswith(".meta.json")):
            continue
        if _timestamp_from_name(name):
            history_files.append(path)

    # Retention is defined in terms of snapshots (timestamps), not individual files.
    by_ts: dict[str, list[Path]] = {}
    for path in history_files:
        ts = _timestamp_from_name(path.name)
        if not ts:
            continue
        by_ts.setdefault(ts, []).append(path)

    before = len(by_ts)
    if before <= keep_last:
        return before, 0

    timestamps = sorted(by_ts.keys(), reverse=True)
    keep_ts = set(timestamps[: max(int(keep_last), 0)])

    deleted = 0
    for ts, paths in by_ts.items():
        if ts in keep_ts:
            continue
        removed_any = False
        for path in paths:
            try:
                path.unlink(missing_ok=True)
                removed_any = True
            except Exception:
                # Best effort; retention is enforced on every sync so we'll try again next time.
                continue
        if removed_any:
            deleted += 1
    return before, deleted


def _prune_inventory_db(serial: str, *, keep_last: int) -> tuple[int, int]:
    """Prune device inventory snapshot history in DB for one device serial.

    Returns (before_count, deleted_count).
    """
    if not inventory_repo.ensure_tables():
        return 0, 0
    keep_last = max(int(keep_last), 0)
    try:
        rows = run_sql(
            """
            SELECT snapshot_id
            FROM device_inventory_snapshots
            WHERE device_serial=%s
            ORDER BY snapshot_id DESC
            """,
            (serial,),
            fetch="all",
        ) or []
    except Exception:
        return 0, 0
    snapshot_ids = [int(r[0]) for r in rows if r and r[0] is not None]
    before = len(snapshot_ids)
    if before <= keep_last:
        return before, 0
    delete_ids = snapshot_ids[keep_last:]
    if not delete_ids:
        return before, 0

    placeholders = ", ".join(["%s"] * len(delete_ids))
    try:
        with database_session() as engine:
            with engine.transaction():
                run_sql(
                    f"DELETE FROM device_inventory WHERE snapshot_id IN ({placeholders})",
                    tuple(delete_ids),
                )
                run_sql(
                    f"DELETE FROM device_inventory_snapshots WHERE snapshot_id IN ({placeholders})",
                    tuple(delete_ids),
                )
        return before, len(delete_ids)
    except Exception:
        return before, 0


def _enforce_inventory_retention(serial: str, *, keep_last: int = _INVENTORY_RETENTION_N) -> None:
    """Enforce inventory retention for both DB and filesystem (Paper #2)."""
    db_before, db_deleted = _prune_inventory_db(serial, keep_last=keep_last)
    fs_before, fs_deleted = _prune_inventory_files(serial, keep_last=keep_last)

    before = db_before if db_before else fs_before
    deleted = db_deleted if db_before else fs_deleted

    # Deterministic, grep-friendly audit line (PM-locked).
    log.info(
        f"RETENTION inventory device={serial} policy=N={keep_last} "
        f"before={before} kept={keep_last} deleted={deleted}",
        category="inventory",
        extra={
            "device_serial": serial,
            "policy_keep_last": keep_last,
            "db_before": db_before,
            "db_deleted": db_deleted,
            "fs_before": fs_before,
            "fs_deleted": fs_deleted,
        },
    )


def get_inventory_retention_status(serial: str, *, keep_last: int = _INVENTORY_RETENTION_N) -> dict[str, int | str]:
    """Return best-effort retention status for operator visibility (not audit truth).

    The paper/audit contract is the structured log line emitted by retention itself.
    This helper is for CLI reassurance that retention is active and bounded.
    """
    inv_dir = _STATE_ROOT / serial / "inventory"

    # FS: history snapshots only (inventory_<timestamp>*.json + .meta.json).
    fs_files = 0
    fs_snapshots: set[str] = set()
    if inv_dir.exists():
        for path in inv_dir.iterdir():
            if not path.is_file():
                continue
            name = path.name
            if not name.startswith("inventory_"):
                continue
            if not (name.endswith(".json") or name.endswith(".meta.json")):
                continue
            # Count only timestamped history, not latest pointers.
            rest = name[len("inventory_") :]
            ts = rest.split(".", 1)[0]
            if len(ts) == 15 and "-" in ts:
                fs_files += 1
                fs_snapshots.add(ts)

    # DB: snapshot row count for the device.
    db_snapshots = 0
    try:
        rows = run_sql(
            "SELECT COUNT(*) FROM device_inventory_snapshots WHERE device_serial=%s",
            (serial,),
            fetch="one",
        )
        if rows and rows[0] is not None:
            db_snapshots = int(rows[0])
    except Exception:
        db_snapshots = 0

    return {
        "device_serial": serial,
        "policy_keep_last": int(keep_last),
        "db_snapshots": int(db_snapshots),
        # Report snapshot count as the primary bounded metric; file count is diagnostic only.
        "fs_snapshots": int(len(fs_snapshots)),
        "fs_history_files": int(fs_files),
        "inventory_dir": str(inv_dir),
    }


def _normalise_hash_token(*values: object) -> str:
    parts = []
    for value in values:
        if value is None:
            parts.append("")
        else:
            parts.append(str(value))
    return "|".join(parts)


def hash_rows(rows: Iterable[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    tokens = []
    for row in rows:
        tokens.append(
            _normalise_hash_token(
                row.get("package_name"),
                row.get("version_name"),
                row.get("version_code"),
                row.get("primary_path"),
            )
        )
    for token in sorted(tokens):
        digest.update(token.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def load_latest_inventory(serial: str) -> dict[str, object | None]:
    """Return the most recently persisted inventory snapshot payload if available."""
    latest_file = _STATE_ROOT / serial / "inventory" / "latest.json"
    if not latest_file.exists():
        return None

    try:
        return json.loads(latest_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning(
            f"Failed to parse {latest_file.relative_to(Path.cwd())}",
            category="device",
        )
        return None


def load_latest_snapshot_meta(serial: str) -> inventory_meta.InventoryMeta | None:
    """Return lightweight metadata for the most recent inventory snapshot."""
    return inventory_meta.load_latest(serial)


def load_canonical_metadata(package_names: Iterable[str]) -> dict[str, dict[str, object]]:
    """Fetch canonical definitions keyed by package name."""

    normalised = sorted({str(name).lower() for name in package_names if name})
    if not normalised:
        return {}

    placeholders = ", ".join(["%s"] * len(normalised))

    def _build_query(include_profiles: bool) -> str:
        profile_select = (
            "            d.profile_key,\n            p.display_name AS profile_name,\n"
            "            d.publisher_key,\n            pub.display_name AS publisher_name"
            if include_profiles
            else "            NULL AS profile_key,\n            NULL AS profile_name,\n"
                 "            NULL AS publisher_key,\n            NULL AS publisher_name"
        )
        profile_join = (
            "            LEFT JOIN android_app_profiles p ON p.profile_key = d.profile_key\n"
            "            LEFT JOIN android_app_publishers pub ON pub.publisher_key = d.publisher_key\n"
            if include_profiles
            else ""
        )
        return f"""
            SELECT
                LOWER(d.package_name) AS package_key,
                d.display_name,
                d.category_id,
                c.category_name,
                {profile_select}
            FROM apps d
            LEFT JOIN android_app_categories c ON c.category_id = d.category_id
{profile_join}            WHERE LOWER(d.package_name) IN ({placeholders})
        """

    rows: list[dict[str, object]]
    query = _build_query(include_profiles=True)
    try:
        rows = run_sql(query, tuple(normalised), fetch="all", dictionary=True) or []
    except RuntimeError as exc:
        if "Unknown column 'd.profile_key'" not in str(exc):
            raise
        log.warning(
            "Profiles unsupported by current apps schema; continuing without profile metadata.",
            category="inventory",
        )
        fallback_query = _build_query(include_profiles=False)
        rows = run_sql(fallback_query, tuple(normalised), fetch="all", dictionary=True) or []
    canonical: dict[str, dict[str, object]] = {}
    for row in rows:
        key = str(row.get("package_key") or "").lower()
        if not key:
            continue
        canonical[key] = {
            "app_name": row.get("display_name"),
            "category_id": row.get("category_id"),
            "category_name": row.get("category_name"),
            "profile_key": row.get("profile_key"),
            "profile_name": row.get("profile_name"),
            "publisher_key": row.get("publisher_key"),
            "publisher_name": row.get("publisher_name"),
        }
    return canonical


@dataclass
class PersistedSnapshot:
    path: Path
    snapshot_id: int | None
    persisted_rows: int


def persist_scoped_snapshot(
    serial: str,
    rows: list[dict[str, object]],
    *,
    scope_id: str,
    package_hash: str | None = None,
    package_list_hash: str | None = None,
    package_signature_hash: str | None = None,
    build_fingerprint: str | None = None,
    duration_seconds: float | None = None,
) -> PersistedSnapshot:
    """Persist a scoped inventory snapshot under data/state/<serial>/inventory/scoped/.

    This is filesystem-only:
    - does NOT update inventory/latest.json (canonical snapshot pointer)
    - does NOT write to the database
    """

    captured_at = datetime.now(UTC)
    timestamp = captured_at.strftime("%Y%m%d-%H%M%S")
    device_dir = _STATE_ROOT / serial / "inventory" / "scoped"
    device_dir.mkdir(parents=True, exist_ok=True)

    normalized_rows: list[dict[str, object]] = []
    for entry in rows:
        if not isinstance(entry, dict):
            continue
        raw_name = entry.get("package_name")
        if isinstance(raw_name, str) and raw_name.strip():
            cleaned = normalize_package_name(raw_name, context="inventory")
            if cleaned and cleaned != raw_name:
                entry = dict(entry)
                entry["raw_package_name"] = raw_name
                entry["package_name"] = cleaned
        normalized_rows.append(entry)

    payload: dict[str, object] = {
        "generated_at": captured_at.isoformat().replace("+00:00", "Z"),
        "device_serial": serial,
        "snapshot_type": "scoped",
        "scope_id": str(scope_id),
        "package_count": len(normalized_rows),
        "packages": normalized_rows,
    }
    if package_hash:
        payload["package_hash"] = package_hash
    if package_list_hash:
        payload["package_list_hash"] = package_list_hash
    if package_signature_hash:
        payload["package_signature_hash"] = package_signature_hash
    if build_fingerprint:
        payload["build_fingerprint"] = build_fingerprint
    if duration_seconds is not None:
        payload["duration_seconds"] = duration_seconds

    slug = re.sub(r"[^a-zA-Z0-9_\\-]+", "_", str(scope_id).strip())[:40] or "scope"
    target_file = device_dir / f"inventory_scoped_{slug}_{timestamp}.json"
    payload_text = json.dumps(payload, indent=2, sort_keys=True)
    target_file.write_text(payload_text, encoding="utf-8")

    latest_scoped = device_dir / f"latest_scoped_{slug}.json"
    latest_scoped.write_text(payload_text, encoding="utf-8")

    resolved_path = target_file.resolve()
    try:
        display_path = resolved_path.relative_to(Path.cwd())
    except ValueError:
        display_path = resolved_path

    # Best-effort retention for scoped history files (separate from canonical inventory retention).
    try:
        scoped_files = sorted([p for p in device_dir.glob(f"inventory_scoped_{slug}_*.json") if p.is_file()], reverse=True)
        for p in scoped_files[_INVENTORY_RETENTION_N :]:
            p.unlink(missing_ok=True)
    except Exception:
        pass

    log.info(f"Scoped inventory written to {display_path}", category="device")
    return PersistedSnapshot(path=display_path, snapshot_id=None, persisted_rows=len(normalized_rows))


def persist_snapshot(
    serial: str,
    rows: list[dict[str, object]],
    *,
    package_hash: str | None = None,
    package_list_hash: str | None = None,
    package_signature_hash: str | None = None,
    build_fingerprint: str | None = None,
    duration_seconds: float | None = None,
    snapshot_type: str = "full",
    scope_hash: str | None = None,
    filename_suffix: str | None = None,
    collection_stats: object | None = None,
    delta: object | None = None,
) -> PersistedSnapshot:
    """Persist inventory information under the state directory and database."""
    captured_at = datetime.now(UTC)
    timestamp = captured_at.strftime("%Y%m%d-%H%M%S")
    device_dir = _STATE_ROOT / serial / "inventory"
    device_dir.mkdir(parents=True, exist_ok=True)

    normalized_rows: list[dict[str, object]] = []
    for entry in rows:
        if not isinstance(entry, dict):
            continue
        raw_name = entry.get("package_name")
        if isinstance(raw_name, str) and raw_name.strip():
            cleaned = normalize_package_name(raw_name, context="inventory")
            if cleaned and cleaned != raw_name:
                entry = dict(entry)
                entry["raw_package_name"] = raw_name
                entry["package_name"] = cleaned
        normalized_rows.append(entry)

    payload: dict[str, object] = {
        "generated_at": captured_at.isoformat().replace("+00:00", "Z"),
        "device_serial": serial,
        "package_count": len(normalized_rows),
        "packages": normalized_rows,
    }

    if snapshot_type:
        payload["snapshot_type"] = snapshot_type
    if scope_hash:
        payload["scope_hash"] = scope_hash
    if filename_suffix:
        payload["snapshot_variant"] = filename_suffix

    if package_hash:
        payload["package_hash"] = package_hash
    if package_list_hash:
        payload["package_list_hash"] = package_list_hash
    if package_signature_hash:
        payload["package_signature_hash"] = package_signature_hash
    if build_fingerprint:
        payload["build_fingerprint"] = build_fingerprint
    if duration_seconds is not None:
        payload["duration_seconds"] = duration_seconds
    if collection_stats is not None:
        identity_source = getattr(collection_stats, "identity_source", None)
        identity_quality = getattr(collection_stats, "identity_quality", None)
        if isinstance(identity_source, str) and identity_source:
            payload["identity_source"] = identity_source
        if isinstance(identity_quality, str) and identity_quality:
            payload["identity_quality"] = identity_quality

    suffix_segment = f".{filename_suffix}" if filename_suffix else ""
    target_file = device_dir / f"inventory_{timestamp}{suffix_segment}.json"
    payload_text = json.dumps(payload, indent=2, sort_keys=True)
    target_file.write_text(payload_text, encoding="utf-8")

    latest_file = device_dir / "latest.json"
    latest_file.write_text(payload_text, encoding="utf-8")

    latest_suffix_file: Path | None = None
    if filename_suffix:
        latest_suffix_file = device_dir / f"latest{suffix_segment}.json"
        latest_suffix_file.write_text(payload_text, encoding="utf-8")

    resolved_path = target_file.resolve()
    try:
        display_path = resolved_path.relative_to(Path.cwd())
    except ValueError:
        display_path = resolved_path

    snapshot_id: int | None = None
    persisted = 0
    try:
        with database_session() as engine:
            with engine.transaction():
                snapshot_id = inventory_repo.create_snapshot(
                    serial,
                    captured_at=captured_at,
                    package_count=len(normalized_rows),
                    duration_seconds=duration_seconds,
                    package_hash=package_hash,
                    package_list_hash=package_list_hash,
                    package_signature_hash=package_signature_hash,
                    build_fingerprint=build_fingerprint,
                    scope_hash=scope_hash,
                    snapshot_type=snapshot_type,
                    scope_variant=filename_suffix,
                    scope_size=len(normalized_rows),
                    extras={
                        "snapshot_path": str(display_path),
                        "identity_source": payload.get("identity_source"),
                        "identity_quality": payload.get("identity_quality"),
                    },
                )
                if snapshot_id:
                    persisted = inventory_repo.replace_packages(snapshot_id, serial, normalized_rows)
                    if persisted != len(normalized_rows):
                        log.warning(
                            "Inventory persistence mismatch; expected rows not written.",
                            category="database",
                            extra={
                                "snapshot_id": snapshot_id,
                                "device_serial": serial,
                                "expected_rows": len(normalized_rows),
                                "persisted_rows": persisted,
                            },
                        )
                        raise RuntimeError(
                            f"Inventory persistence mismatch (expected {len(normalized_rows)}, got {persisted})."
                        )
                    payload["snapshot_id"] = snapshot_id
        if snapshot_id:
            refreshed_payload = json.dumps(payload, indent=2, sort_keys=True)
            target_file.write_text(refreshed_payload, encoding="utf-8")
            latest_file.write_text(refreshed_payload, encoding="utf-8")
            if latest_suffix_file is not None:
                latest_suffix_file.write_text(refreshed_payload, encoding="utf-8")
            log.info(
                f"Inventory snapshot {snapshot_id} stored ({persisted} packages)",
                category="device",
                extra={"snapshot_id": snapshot_id, "device_serial": serial},
            )
    except Exception as exc:  # pragma: no cover - defensive
        snapshot_id = None
        log.warning(
            f"Failed to persist inventory snapshot to database: {exc}",
            category="database",
        )

    log.info(
        f"Inventory written to {display_path}",
        category="device",
    )
    delta_new = getattr(delta, "new_count", None) if delta else None
    delta_removed = getattr(delta, "removed_count", None) if delta else None
    delta_updated = getattr(delta, "updated_count", None) if delta else None
    delta_changed = getattr(delta, "changed_packages_count", None) if delta else None
    delta_split = getattr(delta, "split_delta", None) if delta else None

    meta = inventory_meta.InventoryMeta(
        serial=serial,
        captured_at=captured_at,
        package_count=len(rows),
        package_list_hash=package_list_hash,
        package_signature_hash=package_signature_hash,
        build_fingerprint=build_fingerprint,
        duration_seconds=duration_seconds,
        snapshot_type=snapshot_type,
        scope_hash=scope_hash,
        scope_size=len(rows),
        snapshot_id=snapshot_id,
        delta_new=delta_new,
        delta_removed=delta_removed,
        delta_updated=delta_updated,
        delta_changed_count=delta_changed,
        delta_split_delta=delta_split,
        delta_details=delta if delta is not None else None,
    )
    meta.write_files(timestamp, suffix=filename_suffix)

    # Phase A closure requirement: enforce bounded snapshot growth on every sync (DB + filesystem).
    _enforce_inventory_retention(serial, keep_last=_INVENTORY_RETENTION_N)

    return PersistedSnapshot(path=display_path, snapshot_id=snapshot_id, persisted_rows=persisted)


__all__ = [
    "hash_rows",
    "load_latest_inventory",
    "load_latest_snapshot_meta",
    "persist_snapshot",
    "persist_scoped_snapshot",
    "load_canonical_metadata",
    "PersistedSnapshot",
]
