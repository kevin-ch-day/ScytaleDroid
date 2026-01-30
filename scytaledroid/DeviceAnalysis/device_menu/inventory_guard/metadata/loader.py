"""Load inventory metadata for guard decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from scytaledroid.DeviceAnalysis import adb_devices, adb_packages
from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.DeviceAnalysis import inventory as inventory_module
from scytaledroid.DeviceAnalysis import inventory_meta

from ..constants import INVENTORY_STALE_SECONDS
from ..utils import coerce_float, coerce_int, humanize_seconds
from .normalizers import normalize_scope_entries
from .delta import build_package_delta_summary


def get_latest_inventory_metadata(
    serial: Optional[str],
    *,
    with_current_state: bool = False,
    scope_packages: Optional[Sequence[object]] = None,
    scope_id: str = "last_scope",
) -> Optional[Dict[str, object]]:
    if not serial:
        return None

    snapshot_meta = inventory_meta.load_latest(serial)
    snapshot_payload: Optional[Dict[str, object]] = None
    snapshot_packages: Optional[List[Dict[str, object]]] = None

    package_count: Optional[int]
    scope_hashes: Optional[Dict[str, str]] = None
    snapshot_type: Optional[str] = None
    snapshot_scope_hash: Optional[str] = None
    snapshot_scope_size: Optional[int] = None
    snapshot_id: Optional[int] = None
    if snapshot_meta:
        timestamp = snapshot_meta.captured_at
        package_count = snapshot_meta.package_count
        snapshot_id = snapshot_meta.snapshot_id
        package_list_hash = snapshot_meta.package_list_hash
        package_signature_hash = snapshot_meta.package_signature_hash
        build_fingerprint = snapshot_meta.build_fingerprint
        duration_seconds = snapshot_meta.duration_seconds
        scope_hashes = snapshot_meta.scope_hashes
        snapshot_type = snapshot_meta.snapshot_type
        snapshot_scope_hash = snapshot_meta.scope_hash
        snapshot_scope_size = snapshot_meta.scope_size
        if with_current_state:
            snapshot_payload_candidate = inventory_module.load_latest_inventory(serial)
            if isinstance(snapshot_payload_candidate, dict):
                packages_candidate = snapshot_payload_candidate.get("packages")
                if isinstance(packages_candidate, list):
                    snapshot_packages = packages_candidate  # type: ignore[assignment]
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

        snapshot_identifier = snapshot.get("snapshot_id")
        if isinstance(snapshot_identifier, (int, float)):
            snapshot_id = int(snapshot_identifier)
        elif isinstance(snapshot_identifier, str) and snapshot_identifier.isdigit():
            snapshot_id = int(snapshot_identifier)
        else:
            snapshot_id = None

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
                snapshot_packages = packages_list

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

        snapshot_type_value = snapshot.get("snapshot_type") or snapshot.get("type")
        if isinstance(snapshot_type_value, str) and snapshot_type_value:
            snapshot_type = snapshot_type_value
        scope_hash_value = snapshot.get("scope_hash")
        if isinstance(scope_hash_value, str) and scope_hash_value:
            snapshot_scope_hash = scope_hash_value
        scope_size_value = snapshot.get("scope_size")
        if isinstance(scope_size_value, int):
            snapshot_scope_size = scope_size_value
        elif isinstance(scope_size_value, str) and scope_size_value.isdigit():
            snapshot_scope_size = int(scope_size_value)

    metadata: Dict[str, object] = {"timestamp": timestamp}
    if snapshot_id is not None:
        metadata["snapshot_id"] = snapshot_id
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
    if scope_hashes:
        metadata["scope_hashes"] = dict(scope_hashes)
    if snapshot_type:
        metadata["snapshot_type"] = snapshot_type
    if snapshot_scope_hash:
        metadata["scope_hash"] = snapshot_scope_hash
    if snapshot_scope_size is not None:
        metadata["snapshot_scope_size"] = snapshot_scope_size
    # Propagate last-run delta info (added/removed/updated) from the snapshot meta.
    for field in (
        "delta_new",
        "delta_removed",
        "delta_updated",
        "delta_changed_count",
        "delta_split_delta",
    ):
        value = getattr(snapshot_meta, field, None) if snapshot_meta else None
        if value is not None:
            metadata[field] = value

    if snapshot_meta and getattr(snapshot_meta, "delta_details", None) is not None:
        metadata["delta"] = snapshot_meta.delta_details

    normalized_scope = normalize_scope_entries(scope_packages) if scope_packages else []
    resolved_scope_id = scope_id
    expected_scope_hash: Optional[str] = None

    if normalized_scope:
        expected_scope_hash = inventory_meta.compute_scope_hash(normalized_scope)
        if expected_scope_hash and scope_id == "last_scope":
            resolved_scope_id = f"scope:{expected_scope_hash[:12]}"

    previous_scope_hash: Optional[str] = None
    scope_hash_changed = False
    subset_scope_match = False
    if normalized_scope:
        metadata["scope_hash_id"] = resolved_scope_id
        if expected_scope_hash:
            metadata["expected_scope_hash"] = expected_scope_hash
        if scope_hashes:
            previous_scope_hash = scope_hashes.get(resolved_scope_id)
            if previous_scope_hash:
                metadata["previous_scope_hash"] = previous_scope_hash
                if expected_scope_hash:
                    scope_hash_changed = expected_scope_hash != previous_scope_hash
        if (
            snapshot_type == "subset"
            and snapshot_scope_hash
            and expected_scope_hash
            and snapshot_scope_hash == expected_scope_hash
        ):
            subset_scope_match = True
            scope_hash_changed = False
        metadata["scope_hash_changed"] = scope_hash_changed

        if (
            serial
            and scope_id != resolved_scope_id
            and scope_hashes
            and scope_id in scope_hashes
        ):
            removed_map = inventory_meta.update_scope_hash(serial, scope_id, None)
            if removed_map is not None:
                scope_hashes = removed_map
                metadata["scope_hashes"] = removed_map

        if serial and expected_scope_hash:
            updated = inventory_meta.update_scope_hash(
                serial, resolved_scope_id, expected_scope_hash
            )
            if updated is not None:
                metadata["scope_hashes"] = updated
                scope_hashes = updated
    else:
        metadata.setdefault("scope_hash_changed", False)

    metadata["subset_scope_match"] = subset_scope_match

    if not with_current_state:
        return metadata

    current_signatures = adb_packages.list_packages_with_versions(serial)
    current_names = [name for name, _, _ in current_signatures]
    current_count = len(current_signatures)
    current_hash = inventory_meta.compute_name_hash(current_names)
    current_signature_hash = inventory_meta.compute_signature_hash(current_signatures)

    device_props = adb_devices.get_basic_properties(serial)
    current_fingerprint = None
    if device_props:
        current_fingerprint = device_props.get("build_fingerprint")

    packages_changed = False
    recorded_delta = coerce_int(metadata.get("delta_changed_count"))
    if recorded_delta is None and metadata.get("delta") is not None:
        delta_obj = metadata.get("delta")
        if isinstance(delta_obj, dict):
            recorded_delta = coerce_int(delta_obj.get("changed"))
        else:
            recorded_delta = coerce_int(
                getattr(delta_obj, "changed_packages_count", None)
            )
    if snapshot_type != "subset":
        # If the last sync recorded zero changes, treat that as authoritative and
        # do not mark the snapshot as changed unless scope/hash/fingerprint differ.
        if recorded_delta == 0:
            packages_changed = False
            # Clear any old delta summaries to avoid noisy downstream warnings.
            metadata.pop("package_delta_summary", None)
        else:
            if package_signature_hash and current_signature_hash:
                packages_changed = package_signature_hash != current_signature_hash
            elif package_list_hash and current_hash:
                packages_changed = package_list_hash != current_hash
            elif package_count is not None and package_count != current_count:
                packages_changed = True

    fingerprint_changed = False
    if build_fingerprint and current_fingerprint:
        fingerprint_changed = build_fingerprint != current_fingerprint

    metadata["current_package_count"] = current_count
    if current_hash:
        metadata["current_package_hash"] = current_hash
    if current_signature_hash:
        metadata["current_package_signature_hash"] = current_signature_hash
    if current_fingerprint:
        metadata["current_build_fingerprint"] = current_fingerprint
    metadata["build_fingerprint_changed"] = fingerprint_changed

    estimated_duration = None
    if duration_seconds and package_count and current_count:
        per_package = duration_seconds / max(package_count, 1)
        estimated_duration = per_package * max(current_count, 1)
    elif duration_seconds:
        estimated_duration = duration_seconds

    if estimated_duration is not None:
        metadata["estimated_duration_seconds"] = estimated_duration

    current_scope_hash = None
    if normalized_scope and expected_scope_hash:
        scope_names = {entry["package_name"] for entry in normalized_scope}
        filtered_scope: List[Dict[str, object]] = []
        for name, version_code, _ in current_signatures:
            if name in scope_names:
                filtered_scope.append(
                    {"package_name": name, "version_code": version_code}
                )

        current_scope_hash = inventory_meta.compute_scope_hash(filtered_scope)
        if current_scope_hash:
            metadata["current_scope_hash"] = current_scope_hash

        scope_changed = bool(
            expected_scope_hash
            and current_scope_hash
            and expected_scope_hash != current_scope_hash
        )
        metadata["scope_changed"] = scope_changed
    else:
        metadata.setdefault("scope_changed", False)

    if snapshot_type == "subset":
        if subset_scope_match and current_scope_hash:
            packages_changed = current_scope_hash != snapshot_scope_hash
        elif subset_scope_match and not current_scope_hash:
            packages_changed = True
        elif normalized_scope:
            packages_changed = True
        metadata["packages_changed"] = packages_changed
    else:
        metadata["packages_changed"] = packages_changed

    if packages_changed:
        # Only recompute a package delta if we don't have a recorded zero-change
        # delta from the last run. This avoids spurious warnings immediately
        # after a clean sync.
        if recorded_delta != 0:
            package_delta_summary = build_package_delta_summary(
                snapshot_packages,
                current_signatures,
            )
            if package_delta_summary:
                metadata["package_delta_summary"] = package_delta_summary

    final_packages_changed = bool(metadata.get("packages_changed"))
    state_changed = (
        final_packages_changed
        or fingerprint_changed
        or bool(metadata.get("scope_hash_changed"))
    )
    metadata["state_changed"] = state_changed

    return metadata
