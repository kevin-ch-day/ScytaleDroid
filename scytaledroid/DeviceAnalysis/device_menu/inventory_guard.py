"""Inventory freshness helpers for the Device Analysis menu."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

from .. import adb_utils
from .. import inventory as inventory_module
from .. import inventory_meta

INVENTORY_STALE_SECONDS = 600
LONG_RUNNING_SYNC_THRESHOLD = 120
LOW_BATTERY_THRESHOLD = 20


def ensure_recent_inventory(
    serial: str,
    *,
    device_context: Optional[Dict[str, Optional[str]]] = None,
) -> bool:
    metadata = get_latest_inventory_metadata(serial, with_current_state=True)

    timestamp = metadata.get("timestamp") if metadata else None
    state_changed = bool(metadata.get("state_changed")) if metadata else False
    expected_duration = _coerce_float(
        metadata.get("estimated_duration_seconds") if metadata else None
    )

    age_seconds = None
    if timestamp:
        age_seconds = (datetime.now(timezone.utc) - timestamp).total_seconds()
        if age_seconds <= INVENTORY_STALE_SECONDS and not state_changed:
            return True

    if not timestamp:
        refresh_reason = "No inventory snapshot found—capturing before pull."
    elif state_changed and age_seconds is not None and age_seconds <= INVENTORY_STALE_SECONDS:
        refresh_reason = "Device state changed since last inventory—refreshing before pull."
    else:
        refresh_reason = "Inventory snapshot is stale—refreshing before pull."

    print(status_messages.status(refresh_reason, level="info"))

    battery_context = _resolve_battery_context(serial, device_context)
    prompt_message = _build_sync_warning(battery_context, expected_duration)

    if prompt_message:
        print(status_messages.status(prompt_message, level="warn"))
        if not prompt_utils.prompt_yes_no(
            "Run inventory sync before pulling APKs?", default=False
        ):
            print(
                status_messages.status(
                    "APK pull cancelled until inventory sync is run.", level="warn"
                )
            )
            return False
        abort_on_long_running = False
    else:
        abort_on_long_running = True

    def _execute_sync(abort_on_threshold: bool) -> Tuple[bool, Optional[float]]:
        nonlocal expected_duration

        aborted = False
        latest_estimate = expected_duration
        last_reported = -5.0

        def _handle_progress(event: Dict[str, object]) -> bool:
            nonlocal aborted, latest_estimate, last_reported

            phase = event.get("phase")
            estimated_total = _coerce_float(event.get("estimated_total_seconds")) or latest_estimate

            if phase == "start":
                total = event.get("total")
                if isinstance(total, int) and total > 0:
                    message = f"Syncing {total} packages..."
                else:
                    message = "Syncing packages..."
                print(status_messages.status(message, level="info"))
                if estimated_total is not None:
                    latest_estimate = estimated_total
                if (
                    abort_on_threshold
                    and estimated_total
                    and estimated_total > LONG_RUNNING_SYNC_THRESHOLD
                ):
                    aborted = True
                    return False

            elif phase == "progress":
                percentage = event.get("percentage")
                eta_seconds = _coerce_float(event.get("eta_seconds"))
                if isinstance(percentage, (int, float)):
                    percent_value = float(percentage)
                    if percent_value >= 100 or percent_value - last_reported >= 5:
                        last_reported = percent_value
                        if eta_seconds is not None:
                            eta_text = humanize_seconds(eta_seconds)
                            message = f"Sync progress: {percent_value:.1f}% (ETA {eta_text})"
                        else:
                            message = f"Sync progress: {percent_value:.1f}%"
                        print(status_messages.status(message, level="info"))
                elif eta_seconds is not None:
                    eta_text = humanize_seconds(eta_seconds)
                    print(
                        status_messages.status(
                            f"Sync progress (ETA {eta_text})", level="info"
                        )
                    )

                elapsed_seconds = _coerce_float(event.get("elapsed_seconds"))
                if eta_seconds is not None and eta_seconds > 0:
                    if elapsed_seconds is not None:
                        latest_estimate = eta_seconds + elapsed_seconds
                    else:
                        latest_estimate = eta_seconds
                elif estimated_total is not None:
                    latest_estimate = estimated_total

                if (
                    abort_on_threshold
                    and latest_estimate
                    and latest_estimate > LONG_RUNNING_SYNC_THRESHOLD
                ):
                    aborted = True
                    return False

            elif phase == "complete":
                elapsed = _coerce_float(event.get("elapsed_seconds"))
                if elapsed is not None:
                    message = f"Inventory sync completed in {humanize_seconds(elapsed)}."
                else:
                    message = "Inventory sync completed."
                print(status_messages.status(message, level="success"))

            return True

        try:
            inventory_module.run_inventory_sync(
                serial,
                interactive=False,
                progress_callback=_handle_progress,
                expected_total_seconds=expected_duration,
            )
        except inventory_module.InventorySyncAborted:
            if not aborted:
                raise
        return aborted, latest_estimate

    aborted, estimate = _execute_sync(abort_on_long_running)
    if aborted:
        warning = _build_long_running_warning(estimate)
        print(status_messages.status(warning, level="warn"))
        if not prompt_utils.prompt_yes_no("Continue with inventory sync?", default=False):
            print(
                status_messages.status(
                    "APK pull cancelled until inventory sync is run.", level="warn"
                )
            )
            return False
        if estimate:
            expected_duration = estimate
        aborted, estimate = _execute_sync(False)

    return True


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

        package_count = _coerce_int(snapshot.get("package_count"))
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

        packages_list = None
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

        duration_seconds = _coerce_float(snapshot.get("duration_seconds"))

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
    return f"synced {humanize_seconds(age_seconds)} ago"


def format_pull_hint(serial: Optional[str]) -> str:
    if not serial:
        return "requires device"
    metadata = get_latest_inventory_metadata(serial)
    if not metadata or not metadata.get("timestamp"):
        return "needs inventory sync"
    count = metadata.get("package_count")
    if isinstance(count, int):
        return f"inventory ready ({count} packages)"
    if isinstance(count, str) and count.isdigit():
        return f"inventory ready ({int(count)} packages)"
    return "inventory ready"


def humanize_seconds(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _build_sync_warning(
    battery_context: Dict[str, Optional[object]],
    expected_duration: Optional[float],
) -> Optional[str]:
    reasons: List[str] = []

    level = battery_context.get("level")
    is_charging = bool(battery_context.get("is_charging"))
    if isinstance(level, int) and level < LOW_BATTERY_THRESHOLD:
        if is_charging:
            reasons.append(f"battery is low ({level}%, charging)")
        else:
            reasons.append(f"battery is low ({level}%)")

    if expected_duration and expected_duration > LONG_RUNNING_SYNC_THRESHOLD:
        reasons.append(
            f"sync may take around {humanize_seconds(expected_duration)}"
        )

    if not reasons:
        return None

    joined = " and ".join(reasons)
    return f"Inventory sync {joined}."


def _build_long_running_warning(estimate: Optional[float]) -> str:
    if estimate and estimate > 0:
        return f"Inventory sync is expected to take {humanize_seconds(estimate)}."
    return "Inventory sync may take longer than usual."


def _coerce_float(value: object) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _coerce_int(value: object) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        try:
            return int(value)
        except ValueError:
            return None
    if isinstance(value, float):
        try:
            return int(value)
        except (OverflowError, ValueError):
            return None
    return None


def _parse_battery_level(raw: Optional[str]) -> Optional[int]:
    if not raw:
        return None
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not digits:
        return None
    try:
        return int(digits)
    except ValueError:
        return None


def _resolve_battery_context(
    serial: str,
    device_context: Optional[Dict[str, Optional[str]]],
) -> Dict[str, Optional[object]]:
    level: Optional[int] = None
    status: Optional[str] = None

    if device_context:
        level = _parse_battery_level(device_context.get("battery_level"))
        status_value = device_context.get("battery_status")
        if isinstance(status_value, str):
            status = status_value

    if level is None or status is None:
        stats = adb_utils.get_device_stats(serial)
        if level is None:
            level = _parse_battery_level(stats.get("battery_level"))
        if status is None:
            status_value = stats.get("battery_status")
            if isinstance(status_value, str):
                status = status_value

    normalized_status = status.lower() if isinstance(status, str) else ""
    is_charging = "charg" in normalized_status

    return {"level": level, "status": status, "is_charging": is_charging}


__all__ = [
    "ensure_recent_inventory",
    "get_latest_inventory_metadata",
    "format_inventory_status",
    "format_pull_hint",
    "humanize_seconds",
]
