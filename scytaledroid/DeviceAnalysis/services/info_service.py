"""Service helpers for device info and reporting."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis import adb_devices, device_manager
from scytaledroid.DeviceAnalysis.device_menu.formatters import (
    format_android_release,
    format_battery,
    format_build_tags,
    format_emulator_flag,
    format_wifi_state,
    prettify_manufacturer,
    prettify_model,
)


def fetch_device_info(active_details: dict[str, str | None | None]) -> dict[str, str]:
    """Return a formatted info dict for the active device."""
    serial = active_details.get("serial") if active_details else device_manager.get_active_serial()
    if not serial:
        return {}

    properties = active_details or adb_devices.get_basic_properties(serial) or {}
    info_rows = {
        "Serial": serial,
        "Device Type": properties.get("device_type", "Unknown"),
        "Manufacturer": prettify_manufacturer(
            properties.get("manufacturer") or properties.get("brand")
        ),
        "Model": prettify_model(properties.get("model") or properties.get("device")),
        "Android Version": format_android_release(properties, include_sdk=True) or "Unknown",
        "SDK Level": properties.get("sdk_level") or "Unknown",
        "Hardware": properties.get("hardware") or "Unknown",
        "Product": properties.get("product") or "Unknown",
        "Build ID": properties.get("build_id") or "Unknown",
        "Build Tags": format_build_tags(properties.get("build_tags")),
        "Chipset": properties.get("chipset") or "Unknown",
        "Battery": format_battery(properties),
        "Wi-Fi": format_wifi_state(properties.get("wifi_state")),
        "Root Access": properties.get("is_rooted") or "Unknown",
        "Emulator": format_emulator_flag(properties.get("is_emulator_flag")),
    }
    return info_rows


__all__ = ["fetch_device_info"]