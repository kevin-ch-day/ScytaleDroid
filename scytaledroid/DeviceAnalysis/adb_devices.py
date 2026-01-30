"""Device discovery and serial selection helpers."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from scytaledroid.DeviceAnalysis import device_info
from scytaledroid.DeviceAnalysis.adb_errors import (
    AdbDeviceNotFoundError,
    AdbDeviceSelectionError,
)


def scan_devices() -> Tuple[List[Dict[str, Optional[str]]], List[str]]:
    """Return devices and warnings gathered during discovery."""
    return device_info.scan_devices()


def list_devices() -> List[Dict[str, Optional[str]]]:
    """Return the list of devices reported by adb."""
    return device_info.list_devices()


def get_device_label(device: Dict[str, Optional[str]]) -> str:
    """Return a short human-readable label for a device entry."""
    return device_info.get_device_label(device)


def build_device_summary(device: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
    """Attach basic properties and derived metadata to a device listing."""
    return device_info.build_device_summary(device)


def get_basic_properties(serial: str) -> Dict[str, str]:
    """Return curated device properties plus derived metadata."""
    return device_info.get_basic_properties(serial)


def resolve_serial(
    devices: List[Dict[str, Optional[str]]],
    requested_serial: Optional[str],
) -> str:
    """Resolve a concrete serial for execution paths."""
    if requested_serial:
        for device in devices:
            if device.get("serial") == requested_serial:
                return requested_serial
        raise AdbDeviceNotFoundError(f"Device serial not found: {requested_serial}")
    if not devices:
        raise AdbDeviceNotFoundError("No connected devices detected")
    if len(devices) > 1:
        serials = [d.get("serial") or "unknown" for d in devices]
        raise AdbDeviceSelectionError(
            f"Multiple devices detected; explicit serial required. Seen: {', '.join(serials)}"
        )
    serial = devices[0].get("serial")
    if not serial:
        raise AdbDeviceNotFoundError("Device serial missing from adb list")
    return serial


__all__ = [
    "scan_devices",
    "list_devices",
    "get_device_label",
    "build_device_summary",
    "get_basic_properties",
    "resolve_serial",
]
