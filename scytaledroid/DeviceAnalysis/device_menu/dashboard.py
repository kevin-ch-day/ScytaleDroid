"""Dashboard rendering helpers for the Device Analysis menu."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from scytaledroid.Utils.DisplayUtils import (
    colors,
    error_panels,
    menu_utils,
    table_utils,
    text_blocks,
)
from scytaledroid.Utils.DisplayUtils.terminal import use_ascii_ui
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from scytaledroid.DeviceAnalysis import adb_utils, device_manager
from .formatters import (
    format_android_release,
    format_battery,
    format_device_line,
    format_wifi_state,
)


def _status_badge(label: str, tone: str = "info") -> str:
    """Return a coloured status chip for quick scanning."""

    palette = colors.get_palette()
    style_map = {
        "success": palette.success,
        "warning": palette.warning,
        "error": palette.error,
        "info": palette.info,
    }
    style = style_map.get(tone, palette.info)
    cleaned = (label or "").strip() or "UNKNOWN"
    marker = "*" if use_ascii_ui() else "●"
    token = f"{marker} {cleaned.upper()}"
    return colors.apply(token, style, bold=True)


def _connection_badge(status: Optional[str]) -> str:
    """Colour-code the aggregate connection status."""

    normalised = (status or "Unknown").strip().upper()
    if normalised in {"CONNECTED", "DEVICE"}:
        tone = "success"
    elif normalised in {"DISCONNECTED", "OFFLINE"}:
        tone = "error"
    else:
        tone = "warning"
    return _status_badge(normalised, tone)


def _state_badge(state: Optional[str]) -> str:
    """Colour-code individual device states."""

    normalised = (state or "unknown").strip().upper()
    if normalised in {"DEVICE", "ONLINE"}:
        tone = "success"
    elif normalised in {"UNAUTHORIZED", "RECOVERY", "SIDELOAD"}:
        tone = "warning"
    elif normalised in {"OFFLINE"}:
        tone = "error"
    else:
        tone = "info"
    return _status_badge(normalised, tone)


def _root_badge(root_state: Optional[str]) -> str:
    """Return a badge for the root detection result."""

    normalised = (root_state or "Unknown").strip().upper()
    if normalised == "YES":
        tone = "success"
    elif normalised == "NO":
        tone = "warning"
    else:
        tone = "info"
    return _status_badge(normalised, tone)


def _device_count_badge(count: int) -> str:
    label = f"{count} device{'s' if count != 1 else ''}"
    tone = "success" if count else "warning"
    return _status_badge(label.upper(), tone)


def _format_metric_line(label: str, value: str, *, width: int = 16) -> str:
    palette = colors.get_palette()
    label_token = colors.apply(label.ljust(width), palette.muted, bold=True)
    return f"{label_token} {value}"


def _overview_card_lines(
    refreshed: str,
    devices_found: int,
    connection_status: str,
    active_details: Optional[Dict[str, Optional[str]]],
    warnings_count: int,
) -> List[str]:
    palette = colors.get_palette()
    lines = [
        _format_metric_line("Refreshed", colors.apply(refreshed, palette.accent, bold=True)),
        _format_metric_line("Devices", _device_count_badge(devices_found)),
        _format_metric_line("Status", _connection_badge(connection_status)),
    ]

    if active_details:
        active_label = format_device_line(active_details, include_release=True)
        lines.append(
            _format_metric_line(
                "Active",
                colors.apply(active_label, palette.text, bold=True),
            )
        )
    else:
        lines.append(_format_metric_line("Active", _status_badge("NONE", "warning")))

    if warnings_count:
        warning_label = "warning" if warnings_count == 1 else "warnings"
        lines.append(
            _format_metric_line(
                "ADB",
                _status_badge(f"{warnings_count} {warning_label.upper()}", "warning"),
            )
        )

    return lines


def _render_overview_card(
    refreshed: str,
    devices_found: int,
    connection_status: str,
    active_details: Optional[Dict[str, Optional[str]]],
    warnings_count: int,
) -> str:
    lines = _overview_card_lines(
        refreshed, devices_found, connection_status, active_details, warnings_count
    )
    return text_blocks.boxed(lines, width=74)


def _styled_value(value: Optional[str], *, highlight: bool = False) -> str:
    palette = colors.get_palette()
    text = value or "Unknown"
    if not value or value.strip().lower() == "unknown":
        return colors.apply("Unknown", palette.muted, bold=True)
    style = palette.accent if highlight else palette.text
    return colors.apply(text, style, bold=highlight)


def _active_device_card(details: Dict[str, Optional[str]]) -> str:
    palette = colors.get_palette()
    serial = details.get("serial") or "Unknown"
    root_badge = _root_badge(details.get("is_rooted"))
    lines = [
        colors.apply("ACTIVE DEVICE", colors.style("header"), bold=True),
        colors.apply(
            format_device_line(details, include_release=True), palette.success, bold=True
        ),
        _format_metric_line("Serial", colors.apply(serial, palette.accent, bold=True)),
        _format_metric_line(
            "Android",
            _styled_value(format_android_release(details, include_sdk=True)),
        ),
        _format_metric_line("Battery", _styled_value(format_battery(details))),
        _format_metric_line("Wi-Fi", _styled_value(format_wifi_state(details.get("wifi_state")))),
        _format_metric_line("Root", root_badge),
    ]
    return text_blocks.boxed(lines, width=74)


def _no_device_card(
    last_summary: Optional[Dict[str, Optional[str]]],
    last_serial: Optional[str],
    devices_found: int,
) -> str:
    palette = colors.get_palette()
    if last_summary:
        last_line = format_device_line(last_summary, include_release=True)
    elif last_serial:
        last_line = last_serial
    else:
        last_line = "Unknown"

    hint = (
        "Use option 3 to connect. Press Enter to refresh."
        if devices_found
        else "Attach a device with USB debugging enabled, then press Enter to refresh."
    )

    lines = [
        colors.apply("NO ACTIVE DEVICE", colors.style("warning"), bold=True),
        colors.apply(
            "Connect a device to unlock inventory, harvesting, and reports.",
            palette.muted,
        ),
        _format_metric_line(
            "Last seen",
            colors.apply(last_line, palette.text if last_line != "Unknown" else palette.muted),
        ),
        colors.apply(hint, palette.hint),
    ]
    return text_blocks.boxed(lines, width=74)


def _device_table_rows(
    summaries: List[Dict[str, Optional[str]]]
) -> List[Tuple[str, str, str, str, str, str]]:
    rows: List[Tuple[str, str, str, str, str, str]] = []
    for summary in summaries:
        label = format_device_line(summary)
        state = _state_badge(summary.get("state"))
        android = format_android_release(summary)
        battery = format_battery(summary)
        wifi = format_wifi_state(summary.get("wifi_state"))
        root_badge = _root_badge(summary.get("is_rooted"))
        rows.append((label, state, android, battery, wifi, root_badge))
    return rows


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
    summaries: List[Dict[str, Optional[str]]],
    active_details: Optional[Dict[str, Optional[str]]],
    warnings: List[str],
    last_refresh_ts: Optional[float],
    serial_map: Dict[str, Dict[str, Optional[str]]],
) -> None:
    devices_found = len(summaries)
    connection_status = device_manager.get_connection_status() or "Unknown"

    refreshed = (
        datetime.fromtimestamp(last_refresh_ts).strftime("%Y-%m-%d %H:%M:%S")
        if last_refresh_ts
        else "Unknown"
    )

    print()
    menu_utils.print_header("Device Dashboard", subtitle="Connected hardware overview")
    overview_card = _render_overview_card(
        refreshed,
        devices_found,
        connection_status,
        active_details,
        len(warnings),
    )
    print(overview_card)

    print()
    if active_details:
        print(_active_device_card(active_details))
    else:
        last_serial = device_manager.get_last_serial()
        last_summary = serial_map.get(last_serial) if last_serial else None
        print(_no_device_card(last_summary, last_serial, devices_found))

    if summaries:
        print()
        print(text_blocks.headline("Detected devices", width=74))
        rows = _device_table_rows(summaries)
        table_utils.render_table(
            ["Device", "State", "Android", "Battery", "Wi-Fi", "Root"],
            rows,
            padding=3,
            accent_first_column=True,
        )

    if warnings:
        distinct_warnings = list(dict.fromkeys(warnings))
        for warning in distinct_warnings:
            log.warning(warning, category="device")
        panel = error_panels.format_panel(
            "ADB warnings",
            "Review the following issues detected during the scan.",
            details=distinct_warnings,
            tone="warning",
            width=74,
        )
        print()
        print(panel)


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
