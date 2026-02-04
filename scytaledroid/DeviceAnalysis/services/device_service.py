"""Headless service helpers for device discovery, summaries, and inventory metadata.

These thin wrappers centralize adb access and metadata retrieval so UI layers
can stay focused on rendering and prompting.
"""

from __future__ import annotations

from datetime import UTC, datetime

from scytaledroid.DeviceAnalysis import (
    adb_devices,
    adb_packages,
    adb_status,
    device_manager,
    inventory_meta,
)
from scytaledroid.DeviceAnalysis.inventory import load_latest_inventory
from scytaledroid.DeviceAnalysis.inventory import runner as inventory_runner
from scytaledroid.DeviceAnalysis.services.models import InventoryStatus


def scan_devices(
    *,
    cache: dict[str, dict[str, str | None | None]] = None,
    refresh_threshold: int = 60,
) -> tuple[
    list[dict[str, str | None]],
    list[str],
    list[dict[str, str | None]],
    dict[str, dict[str, str | None]],
]:
    """Return raw adb devices, warnings, enriched summaries, and a serial map."""

    devices, warnings = adb_devices.scan_devices()
    summary_cache = cache or {}
    summaries, serial_map = build_device_summaries(
        devices,
        summary_cache,
        refresh_threshold=refresh_threshold,
    )
    return devices, warnings, summaries, serial_map


def build_device_summaries(
    devices: list[dict[str, str | None]],
    summary_cache: dict[str, dict[str, str | None]],
    *,
    refresh_threshold: int = 60,
) -> tuple[list[dict[str, str | None]], dict[str, dict[str, str | None]]]:
    """Return summarized device rows with caching for UI display."""
    import time

    summaries: list[dict[str, str | None]] = []
    serial_map: dict[str, dict[str, str | None]] = {}

    for device in devices:
        serial = device.get("serial")
        cached: dict[str, str | None | None] = None
        cache_age = None
        if serial and serial in summary_cache:
            cached = summary_cache[serial]
            cache_time_raw = cached.get("_cache_time")
            try:
                cache_age = time.time() - float(cache_time_raw) if cache_time_raw else None
            except (TypeError, ValueError):
                cache_age = None

        if cached and cache_age is not None and cache_age <= refresh_threshold:
            cached.update({k: v for k, v in device.items() if v is not None})
            summary = cached
        else:
            summary = adb_devices.build_device_summary(device)
            if serial:
                summary["_cache_time"] = time.time()
                summary_cache[serial] = summary

        summaries.append(summary)
        if serial:
            serial_map[serial] = summary

    return summaries, serial_map


def get_active_serial() -> str | None:
    """Expose the active device serial."""
    return device_manager.get_active_serial()


def get_last_serial() -> str | None:
    """Expose the last active device serial for UI hints."""
    return device_manager.get_last_serial()


def get_device_stats(serial: str) -> dict[str, object]:
    """Return device stats from adb for UI helpers."""
    return adb_status.get_device_stats(serial)


def get_basic_properties(serial: str) -> dict[str, str | None]:
    """Return basic device properties for inventory guard metadata."""
    return adb_devices.get_basic_properties(serial)


def list_packages_with_versions(serial: str):
    """Return package signatures for inventory guard metadata."""
    return adb_packages.list_packages_with_versions(serial)


def set_active_serial(serial: str) -> bool:
    """Set the active device if it exists in the adb inventory."""
    return device_manager.set_active_device(serial)


def disconnect() -> None:
    """Forget the active device."""
    device_manager.disconnect()


def resolve_active_device(devices: list[dict[str, str | None]]) -> dict[str, str | None | None]:
    """Return the active device entry if it is still present; otherwise clear it."""
    serial = device_manager.get_active_serial()
    if not serial:
        return None
    for device in devices:
        if device.get("serial") == serial:
            return device
    device_manager.disconnect()
    return None


def _compute_inventory_status(
    meta: dict | None,
    snapshot_meta: inventory_meta.InventoryMeta | None,
) -> InventoryStatus:
    """Compute a unified InventoryStatus from metadata or snapshot."""
    # Local import to avoid circular dependency when services are used headless.
    from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import (
        INVENTORY_STALE_SECONDS,
    )
    from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.utils import humanize_seconds

    ts = None
    pkg_count = None
    pkg_changed = False
    scope_changed = False
    state_changed = False
    fp_changed = False

    if isinstance(meta, dict):
        ts = meta.get("timestamp")
        pkg_count = meta.get("package_count") if isinstance(meta.get("package_count"), int) else None
        pkg_changed = bool(meta.get("packages_changed"))
        scope_changed = bool(meta.get("scope_changed"))
        state_changed = bool(meta.get("state_changed"))
        fp_changed = bool(meta.get("build_fingerprint_changed"))
    if ts is None and snapshot_meta is not None:
        ts = snapshot_meta.captured_at
        pkg_count = snapshot_meta.package_count

    age_seconds: int | None = None
    if isinstance(ts, datetime):
        try:
            if ts.tzinfo is None:
                ts_utc = ts.replace(tzinfo=UTC)
            else:
                ts_utc = ts.astimezone(UTC)
            now_utc = datetime.now(UTC)
            age_seconds = max(0, int((now_utc - ts_utc).total_seconds()))
        except Exception:
            age_seconds = None

    is_stale = bool(age_seconds is not None and age_seconds >= INVENTORY_STALE_SECONDS)
    status_label = "NONE"
    if ts is None:
        status_label = "NONE"
    elif is_stale:
        status_label = "STALE"
    else:
        status_label = "FRESH"

    age_display = humanize_seconds(age_seconds) if age_seconds is not None else "unknown"

    return InventoryStatus(
        last_run_ts=ts if isinstance(ts, datetime) else None,
        package_count=pkg_count,
        age_seconds=age_seconds,
        is_stale=is_stale,
        status_label=status_label,
        age_display=age_display,
        packages_changed=pkg_changed,
        scope_changed=scope_changed,
        state_changed=state_changed,
        fingerprint_changed=fp_changed,
    )


def fetch_inventory_metadata(
    serial: str | None,
    *,
    with_current_state: bool = False,
    scope_packages: list[object | None] = None,
    scope_id: str = "last_scope",
) -> InventoryStatus | None:
    """Return the latest inventory metadata (and optional current-state diff) as InventoryStatus."""
    from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.metadata import (
        get_latest_inventory_metadata,
    )
    meta = get_latest_inventory_metadata(
        serial,
        with_current_state=with_current_state,
        scope_packages=scope_packages,
        scope_id=scope_id,
    )
    snapshot_meta = None
    if serial:
        snapshot_meta = inventory_meta.load_latest(serial)
    return _compute_inventory_status(meta, snapshot_meta)


def sync_inventory(
    serial: str,
    *,
    filter_name: str | None = None,
    filter_fn: callable | None = None,
) -> InventoryStatus:
    """
    Run an inventory sync for the given device serial and return updated status.

    filter_name/filter_fn are passed through to the existing sync helper for scoped syncs.
    """
    inventory_runner.run_full_sync(serial=serial, filter_fn=filter_fn, progress_cb=None)
    # Refresh metadata after sync
    status = fetch_inventory_metadata(serial, with_current_state=True)
    return status or InventoryStatus(
        last_run_ts=None,
        package_count=None,
        age_seconds=None,
        is_stale=False,
        status_label="NONE",
        age_display="unknown",
    )


def fetch_raw_inventory(serial: str | None) -> dict | None:
    """Return the latest inventory payload from disk."""
    if not serial:
        return None
    return load_latest_inventory(serial)


__all__ = [
    "scan_devices",
    "get_active_serial",
    "set_active_serial",
    "disconnect",
    "fetch_inventory_metadata",
    "resolve_active_device",
]
