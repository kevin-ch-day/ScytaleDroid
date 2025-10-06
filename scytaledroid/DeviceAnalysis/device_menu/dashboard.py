"""Dashboard rendering helpers for the Device Analysis menu."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, table_utils, error_panels
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from scytaledroid.DeviceAnalysis import adb_utils, device_manager
from .formatters import (
    format_android_release,
    format_battery,
    format_device_line,
    format_wifi_state,
    prettify_model,
)


def build_device_summaries(
    devices: List[Dict[str, Optional[str]]],
    summary_cache: Dict[str, Dict[str, Optional[str]]],
    *,
    refresh_threshold: int = 60,
) -> Tuple[List[Dict[str, Optional[str]]], Dict[str, Dict[str, Optional[str]]]]:
    summaries: List[Dict[str, Optional[str]]] = []
    serial_map: Dict[str, Dict[str, Optional[str]]] = {}

    for device in devices:
        serial = device.get("serial")
        cached: Optional[Dict[str, Optional[str]]] = None
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
            summary = adb_utils.build_device_summary(device)
            if serial:
                summary["_cache_time"] = time.time()
                summary_cache[serial] = summary

        summaries.append(summary)
        if serial:
            serial_map[serial] = summary

    log.info(
        f"Refreshed device dashboard: {len(summaries)} device(s) detected.",
        category="device",
    )

    return summaries, serial_map


def print_dashboard(
    devices: List[Dict[str, Optional[str]]],
    active_details: Optional[Dict[str, Optional[str]]],
    warnings: List[str],
    last_refresh_ts: Optional[float],
    serial_map: Dict[str, Dict[str, Optional[str]]],
) -> None:
    devices_found = len(devices)
    connection_status = device_manager.get_connection_status() or "Unknown"

    refreshed = (
        datetime.fromtimestamp(last_refresh_ts).strftime("%Y-%m-%d %H:%M:%S")
        if last_refresh_ts
        else "Unknown"
    )

    print()
    menu_utils.print_header("Device Dashboard", subtitle="Connected hardware overview")
    metric_rows = [
        ("Refreshed", refreshed),
        ("Devices Detected", devices_found),
        ("Connection Status", connection_status),
    ]
    menu_utils.print_metrics(metric_rows)
    print()

    if active_details:
        serial = active_details.get("serial") or "Unknown"
        headline = format_device_line(active_details, include_release=True)
        details = [
            f"Serial: {serial}",
            f"Android: {format_android_release(active_details)}",
            f"Battery: {format_battery(active_details)}",
            f"Wi-Fi: {format_wifi_state(active_details.get('wifi_state'))}",
            f"Rooted: {active_details.get('is_rooted') or 'Unknown'}",
        ]
        error_panels.print_success_panel("Active device", headline, details=details)
    else:
        error_panels.print_warning_panel(
            "No active device",
            "No device is currently connected.",
        )
        last_serial = device_manager.get_last_serial()
        if last_serial:
            last_summary = serial_map.get(last_serial)
            if last_summary:
                formatted = format_device_line(last_summary, include_release=True)
                menu_utils.print_hint(f"Last connection: {formatted}")
            else:
                menu_utils.print_hint(f"Last connection: {last_serial}")
        if devices_found:
            menu_utils.print_hint("Use option 3 to connect. Press Enter to refresh.")
        else:
            menu_utils.print_hint(
                "Attach a device with USB debugging enabled, then press Enter to refresh."
            )

    if warnings:
        print()
        for warning in warnings:
            error_panels.print_warning_panel("ADB warning", warning)
            log.warning(warning, category="device")


def resolve_active_device(
    devices: List[Dict[str, Optional[str]]]
) -> Optional[Dict[str, Optional[str]]]:
    serial = device_manager.get_active_serial()
    if not serial:
        return None

    for device in devices:
        if device.get("serial") == serial:
            return device

    device_manager.disconnect()
    return None


__all__ = ["build_device_summaries", "print_dashboard", "resolve_active_device"]
