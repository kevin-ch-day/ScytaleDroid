"""Headless service helpers for device discovery, summaries, and inventory metadata.

These thin wrappers centralize adb access and metadata retrieval so UI layers
can stay focused on rendering and prompting.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from scytaledroid.DeviceAnalysis import adb_utils, device_manager
from scytaledroid.DeviceAnalysis.device_menu.dashboard import build_device_summaries
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.metadata import (
    get_latest_inventory_metadata,
)


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


def fetch_inventory_metadata(
    serial: Optional[str],
    *,
    with_current_state: bool = False,
    scope_packages: Optional[List[object]] = None,
    scope_id: str = "last_scope",
) -> Optional[Dict[str, object]]:
    """Return the latest inventory metadata (and optional current-state diff)."""
    return get_latest_inventory_metadata(
        serial,
        with_current_state=with_current_state,
        scope_packages=scope_packages,
        scope_id=scope_id,
    )


__all__ = [
    "scan_devices",
    "get_active_serial",
    "set_active_serial",
    "disconnect",
    "fetch_inventory_metadata",
]
