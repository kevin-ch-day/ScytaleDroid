"""Headless service helpers for device discovery, summaries, and inventory metadata.

These thin wrappers centralize adb access and metadata retrieval so UI layers
can stay focused on rendering and prompting.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from datetime import datetime

from scytaledroid.DeviceAnalysis import adb_utils, device_manager
from scytaledroid.DeviceAnalysis.device_menu.dashboard import build_device_summaries
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.metadata import (
    get_latest_inventory_metadata,
)
from scytaledroid.DeviceAnalysis.services.models import InventoryStatus
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import (
    INVENTORY_STALE_SECONDS,
)
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.utils import humanize_seconds


def scan_devices(
    *,
    cache: Optional[Dict[str, Dict[str, Optional[str]]]] = None,
    refresh_threshold: int = 60,
) -> Tuple[
    List[Dict[str, Optional[str]]],
    List[str],
    List[Dict[str, Optional[str]]],
    Dict[str, Dict[str, Optional[str]]],
]:
    """Return raw adb devices, warnings, enriched summaries, and a serial map."""

    devices, warnings = adb_utils.scan_devices()
    summary_cache = cache or {}
    summaries, serial_map = build_device_summaries(
        devices,
        summary_cache,
        refresh_threshold=refresh_threshold,
    )
    return devices, warnings, summaries, serial_map


def get_active_serial() -> Optional[str]:
    """Expose the active device serial."""
    return device_manager.get_active_serial()


def set_active_serial(serial: str) -> bool:
    """Set the active device if it exists in the adb inventory."""
    return device_manager.set_active_device(serial)


def disconnect() -> None:
    """Forget the active device."""
    device_manager.disconnect()


def resolve_active_device(devices: List[Dict[str, Optional[str]]]) -> Optional[Dict[str, Optional[str]]]:
    """Return the active device entry if it is still present; otherwise clear it."""
    serial = device_manager.get_active_serial()
    if not serial:
        return None
    for device in devices:
        if device.get("serial") == serial:
            return device
    device_manager.disconnect()
    return None


def fetch_inventory_metadata(
    serial: Optional[str],
    *,
    with_current_state: bool = False,
    scope_packages: Optional[List[object]] = None,
    scope_id: str = "last_scope",
) -> Optional[InventoryStatus]:
    """Return the latest inventory metadata (and optional current-state diff) as InventoryStatus."""
    meta = get_latest_inventory_metadata(
        serial,
        with_current_state=with_current_state,
        scope_packages=scope_packages,
        scope_id=scope_id,
    )
    if not meta:
        return None
    ts = meta.get("timestamp")
    pkg_count = meta.get("package_count") if isinstance(meta.get("package_count"), int) else None
    age_seconds = None
    is_stale = False
    if ts:
        # Ensure ts is naive UTC
        try:
            age_seconds = max(0, int((datetime.utcnow() - ts.replace(tzinfo=None)).total_seconds()))
            is_stale = age_seconds > INVENTORY_STALE_SECONDS
        except Exception:
            age_seconds = None
    status_label = "FRESH" if not is_stale else "STALE"
    age_display = humanize_seconds(age_seconds) if age_seconds is not None else "unknown"
    return InventoryStatus(
        last_run_ts=ts,
        package_count=pkg_count,
        age_seconds=age_seconds,
        is_stale=is_stale,
        status_label=status_label,
        age_display=age_display,
    )


__all__ = [
    "scan_devices",
    "get_active_serial",
    "set_active_serial",
    "disconnect",
    "fetch_inventory_metadata",
    "resolve_active_device",
]
