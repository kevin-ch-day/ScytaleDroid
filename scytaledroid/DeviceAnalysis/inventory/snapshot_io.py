"""Snapshot I/O helpers for inventory (UI-free)."""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, TYPE_CHECKING
from datetime import datetime, timezone

from scytaledroid.Config import app_config
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.DeviceAnalysis import inventory_meta

if TYPE_CHECKING:  # pragma: no cover
    from scytaledroid.DeviceAnalysis.inventory.runner import InventoryDelta
from scytaledroid.Database.db_core import database_session, run_sql
from scytaledroid.Database.db_utils.package_utils import normalize_package_name
from scytaledroid.Database.db_func.harvest import device_inventory as inventory_repo


_STATE_ROOT = Path(app_config.DATA_DIR) / app_config.DEVICE_STATE_DIR


def _normalise_hash_token(*values: object) -> str:
    parts = []
    for value in values:
        if value is None:
            parts.append("")
        else:
            parts.append(str(value))
    return "|".join(parts)


def hash_rows(rows: Iterable[Dict[str, object]]) -> str:
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


def load_latest_inventory(serial: str) -> Optional[Dict[str, object]]:
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


def load_latest_snapshot_meta(serial: str) -> Optional[inventory_meta.InventoryMeta]:
    """Return lightweight metadata for the most recent inventory snapshot."""
    return inventory_meta.load_latest(serial)


def load_canonical_metadata(package_names: Iterable[str]) -> Dict[str, Dict[str, object]]:
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

    rows: List[Dict[str, object]]
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
    canonical: Dict[str, Dict[str, object]] = {}
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


def persist_snapshot(
    serial: str,
    rows: List[Dict[str, object]],
    *,
    package_hash: Optional[str] = None,
    package_list_hash: Optional[str] = None,
    package_signature_hash: Optional[str] = None,
    build_fingerprint: Optional[str] = None,
    duration_seconds: Optional[float] = None,
    snapshot_type: str = "full",
    scope_hash: Optional[str] = None,
    filename_suffix: Optional[str] = None,
    collection_stats: Optional[object] = None,
    delta: Optional[object] = None,
) -> PersistedSnapshot:
    """Persist inventory information under the state directory and database."""
    captured_at = datetime.utcnow().replace(tzinfo=timezone.utc)
    timestamp = captured_at.strftime("%Y%m%d-%H%M%S")
    device_dir = _STATE_ROOT / serial / "inventory"
    device_dir.mkdir(parents=True, exist_ok=True)

    normalized_rows: List[Dict[str, object]] = []
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

    payload: Dict[str, object] = {
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

    suffix_segment = f".{filename_suffix}" if filename_suffix else ""
    target_file = device_dir / f"inventory_{timestamp}{suffix_segment}.json"
    payload_text = json.dumps(payload, indent=2, sort_keys=True)
    target_file.write_text(payload_text, encoding="utf-8")

    latest_file = device_dir / "latest.json"
    latest_file.write_text(payload_text, encoding="utf-8")

    latest_suffix_file: Optional[Path] = None
    if filename_suffix:
        latest_suffix_file = device_dir / f"latest{suffix_segment}.json"
        latest_suffix_file.write_text(payload_text, encoding="utf-8")

    resolved_path = target_file.resolve()
    try:
        display_path = resolved_path.relative_to(Path.cwd())
    except ValueError:
        display_path = resolved_path

    snapshot_id: Optional[int] = None
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

    return PersistedSnapshot(path=display_path, snapshot_id=snapshot_id, persisted_rows=persisted)


__all__ = [
    "hash_rows",
    "load_latest_inventory",
    "load_latest_snapshot_meta",
    "persist_snapshot",
    "load_canonical_metadata",
    "PersistedSnapshot",
]
