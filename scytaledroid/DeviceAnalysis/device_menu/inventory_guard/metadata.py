"""Inventory metadata helpers used by the device menu."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from .. import adb_utils
from .. import inventory as inventory_module
from .. import inventory_meta
from .constants import INVENTORY_STALE_SECONDS
from .utils import coerce_float, coerce_int, humanize_seconds


def get_latest_inventory_metadata(
    serial: Optional[str],
    *,
    with_current_state: bool = False,
) -> Optional[Dict[str, object]]:
    if not serial:
        return None

    snapshot_meta = inventory_meta.load_latest(serial)
    snapshot_payload: Optional[Dict[str, object]] = None

    package_count: Optional[int]
    if snapshot_meta:
        timestamp = snapshot_meta.captured_at
        package_count = snapshot_meta.package_count
        package_list_hash = snapshot_meta.package_list_hash
        package_signature_hash = snapshot_meta.package_signature_hash
        build_fingerprint = snapshot_meta.build_fingerprint
        duration_seconds = snapshot_meta.duration_seconds
    else:
        snapshot = inventory_module.load_latest_inventory(serial)
        if not snapshot:
            return None

        snapshot_payload = snapshot if isinstance(snapshot, dict) else None
        generated_at = snapshot.get("generated_at")
        timestamp = None
        if isinstance(generated_at, str):
            try:
                timestamp = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            except ValueError:
                timestamp = None

        package_count = coerce_int(snapshot.get("package_count"))
        package_list_hash_value = snapshot.get("package_list_hash")
        package_list_hash = (
            package_list_hash_value
            if isinstance(package_list_hash_value, str) and package_list_hash_value
            else None
        )
        package_signature_hash_value = snapshot.get("package_signature_hash")
        package_signature_hash = (
            package_signature_hash_value
            if isinstance(package_signature_hash_value, str) and package_signature_hash_value
            else None
        )

        packages_list: Optional[List[Dict[str, object]]] = None
        if snapshot_payload:
            packages_candidate = snapshot_payload.get("packages")
            if isinstance(packages_candidate, list):
                packages_list = packages_candidate

        if not package_list_hash and packages_list:
            names = [
                str(entry.get("package_name"))
                for entry in packages_list
                if isinstance(entry, dict) and entry.get("package_name")
            ]
            package_list_hash = inventory_meta.compute_name_hash(names)

        if not package_signature_hash and packages_list:
            package_signature_hash = inventory_meta.compute_signature_hash(
                inventory_meta.snapshot_signatures(packages_list)
            )

        build_fingerprint_value = snapshot.get("build_fingerprint")
        build_fingerprint = (
            build_fingerprint_value
            if isinstance(build_fingerprint_value, str)
            else None
        )

        duration_seconds = coerce_float(snapshot.get("duration_seconds"))

    metadata: Dict[str, object] = {"timestamp": timestamp}
    if package_count is not None:
        metadata["package_count"] = package_count
    if package_list_hash:
        metadata["package_list_hash"] = package_list_hash
    if package_signature_hash:
        metadata["package_signature_hash"] = package_signature_hash
    if build_fingerprint:
        metadata["build_fingerprint"] = build_fingerprint
    if duration_seconds is not None:
        metadata["duration_seconds"] = duration_seconds

    if not with_current_state:
        return metadata

    current_signatures = adb_utils.list_packages_with_versions(serial)
    current_names = [name for name, _, _ in current_signatures]
    current_count = len(current_signatures)
    current_hash = inventory_meta.compute_name_hash(current_names)
    current_signature_hash = inventory_meta.compute_signature_hash(current_signatures)

    device_props = adb_utils.get_basic_properties(serial)
    current_fingerprint = None
    if device_props:
        current_fingerprint = device_props.get("build_fingerprint")

    state_changed = False
    if package_signature_hash and current_signature_hash:
        state_changed = package_signature_hash != current_signature_hash
    elif package_list_hash and current_hash:
        state_changed = package_list_hash != current_hash
    elif package_count is not None and package_count != current_count:
        state_changed = True

    if not state_changed and build_fingerprint and current_fingerprint:
        state_changed = build_fingerprint != current_fingerprint

    metadata["current_package_count"] = current_count
    if current_hash:
        metadata["current_package_hash"] = current_hash
    if current_signature_hash:
        metadata["current_package_signature_hash"] = current_signature_hash
    if current_fingerprint:
        metadata["current_build_fingerprint"] = current_fingerprint
    metadata["state_changed"] = state_changed

    estimated_duration = None
    if duration_seconds and package_count and current_count:
        per_package = duration_seconds / max(package_count, 1)
        estimated_duration = per_package * max(current_count, 1)
    elif duration_seconds:
        estimated_duration = duration_seconds

    if estimated_duration is not None:
        metadata["estimated_duration_seconds"] = estimated_duration

    return metadata


def format_inventory_status(serial: Optional[str]) -> str:
    if not serial:
        return "connect device"
    metadata = get_latest_inventory_metadata(serial)
    if not metadata or not metadata.get("timestamp"):
        return "not yet run"
    age_seconds = (datetime.now(timezone.utc) - metadata["timestamp"]).total_seconds()
    if age_seconds < 0:
        age_seconds = 0
    status = f"synced {humanize_seconds(age_seconds)} ago"
    if age_seconds > INVENTORY_STALE_SECONDS:
        status = f"{status} (stale)"
    return status


def format_pull_hint(serial: Optional[str]) -> str:
    if not serial:
        return "requires device"
    metadata = get_latest_inventory_metadata(serial)
    if not metadata or not metadata.get("timestamp"):
        return "needs inventory sync"
    age_seconds = (
        datetime.now(timezone.utc) - metadata["timestamp"]
    ).total_seconds()
    if age_seconds < 0:
        age_seconds = 0
    count = metadata.get("package_count")
    stale = age_seconds > INVENTORY_STALE_SECONDS
    prefix = "inventory stale" if stale else "inventory ready"
    if isinstance(count, int):
        return f"{prefix} ({count} packages)"
    if isinstance(count, str) and count.isdigit():
        return f"{prefix} ({int(count)} packages)"
    return prefix
