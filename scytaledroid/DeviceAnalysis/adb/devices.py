"""Device discovery and serial selection helpers."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis import device_info
from scytaledroid.DeviceAnalysis.adb.errors import (
    AdbDeviceNotFoundError,
    AdbDeviceSelectionError,
)


def scan_devices() -> tuple[list[dict[str, str | None]], list[str]]:
    """Return devices and warnings gathered during discovery."""
    return device_info.scan_devices()


def list_devices() -> list[dict[str, str | None]]:
    """Return the list of devices reported by adb."""
    return device_info.list_devices()


def get_device_label(device: dict[str, str | None]) -> str:
    """Return a short human-readable label for a device entry."""
    return device_info.get_device_label(device)


def build_device_summary(device: dict[str, str | None]) -> dict[str, str | None]:
    """Attach basic properties and derived metadata to a device listing."""
    return device_info.build_device_summary(device)


def get_basic_properties(serial: str) -> dict[str, str]:
    """Return curated device properties plus derived metadata."""
    return device_info.get_basic_properties(serial)


def get_play_services_version(serial: str) -> str | None:
    """Return Google Play services versionName when available."""
    return device_info.get_play_services_version(serial)


def resolve_serial(
    devices: list[dict[str, str | None]],
    requested_serial: str | None,
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
    "get_play_services_version",
    "resolve_serial",
]
