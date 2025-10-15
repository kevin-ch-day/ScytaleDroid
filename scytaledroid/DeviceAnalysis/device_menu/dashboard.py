"""Dashboard rendering helpers for the Device Analysis menu.

This module focuses on compact, badge-driven output that fits reliably
within narrow terminals and avoids multi-line hint panels. The dashboard
header is rendered as a single line with concise status tokens; detailed
cards are discoverable via menu actions rather than always-on panels.
"""

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


# -------------------------
# Badge helpers
# -------------------------
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
    # Prefer a solid bullet when colours are enabled; fall back to ASCII
    # depending on terminal capability otherwise.
    # When colours are enabled (e.g., tests via FORCE_COLOR), prefer a solid bullet
    # to ensure consistent snapshots regardless of Unicode heuristics.
    if colors.colors_enabled():
        marker = "●"
    else:
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


# -------------------------
# Compact header
# -------------------------

def _compact_header(
    *,
    refreshed: str,
    adb_status: str,
    devices_found: int,
    active_line: Optional[str],
    width: Optional[int] = None,
) -> str:
    """Render a single-line dashboard header within the terminal width.

    Example (Unicode mode):
    Device Dashboard — 2025-10-15 11:52:06   ADB: CONNECTED   Detected: 1   Active: moto g 5G (ZY22…)
    """

    palette = colors.get_palette()
    term_width = width or text_blocks.visible_width(" " * 80) or 80
    sep = " - " if use_ascii_ui() else " — "

    title = colors.apply("Device Dashboard", palette.header, bold=True)
    ts = colors.apply(refreshed, palette.accent, bold=True)
    adb = colors.apply(f"ADB: {adb_status}", palette.info, bold=True)
    det = colors.apply(f"Detected: {devices_found}", palette.text)

    parts = [f"{title}{sep}{ts}", adb, det]
    if active_line:
        active_token = colors.apply("Active:", palette.muted, bold=True)
        parts.append(f"{active_token} {colors.apply(active_line, palette.text, bold=True)}")

    joined = "   ".join(parts)
    # Clamp to width without breaking ANSI sequences
    return text_blocks.truncate_visible(joined, term_width)

def _format_metric_line(label: str, value: str, *, width: int = 16) -> str:
    palette = colors.get_palette()
    label_token = colors.apply(label.ljust(width), palette.muted, bold=True)
    return f"{label_token} {value}"


def _no_device_line(devices_found: int) -> str:
    """Single-line guidance shown when there is no active device."""
    if devices_found:
        return "No active device. Use 3 to connect (Enter to refresh)."
    return "No devices detected. Attach a device and press Enter to refresh."


def _styled_value(value: Optional[str], *, highlight: bool = False) -> str:
    palette = colors.get_palette()
    text = value or "Unknown"
    if not value or value.strip().lower() == "unknown":
        return colors.apply("Unknown", palette.muted, bold=True)
    style = palette.accent if highlight else palette.text
    return colors.apply(text, style, bold=highlight)


def _active_device_brief(details: Dict[str, Optional[str]], *, width: int) -> str:
    """Return a concise active device line suitable for the header."""
    label = format_device_line(details, include_release=False)
    return text_blocks.truncate_visible(label, max(10, width // 3))


def _last_seen_brief(
    last_summary: Optional[Dict[str, Optional[str]]], last_serial: Optional[str]
) -> Optional[str]:
    if last_summary:
        return format_device_line(last_summary, include_release=True)
    if last_serial:
        return last_serial
    return None


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

    # Header
    active_line = None
    from scytaledroid.Utils.DisplayUtils.terminal import get_terminal_width
    term_width = get_terminal_width()
    if active_details:
        active_line = _active_device_brief(active_details, width=term_width)
    # Treat presence of active details as connected for header purposes
    header = _compact_header(
        refreshed=refreshed,
        adb_status=(("CONNECTED" if active_details else connection_status) or "").upper(),
        devices_found=devices_found,
        active_line=active_line,
        width=term_width,
    )
    print()
    print(header)

    # One-line guidance when disconnected
    if not active_details:
        last_serial = device_manager.get_last_serial()
        last_summary = serial_map.get(last_serial) if last_serial else None
        last_seen = _last_seen_brief(last_summary, last_serial)
        line = _no_device_line(devices_found)
        if last_seen:
            line = f"{line} Last seen: {last_seen}"
        print(colors.apply(line, colors.get_palette().hint))

    # Device table
    if summaries:
        print()
        print(text_blocks.headline("Detected devices", width=74))
        rows = _device_table_rows(summaries)
        # Promote single device with a left margin indicator
        if len(rows) == 1 and rows[0]:
            label, *rest = rows[0]
            rows[0] = (f"* {label}" if use_ascii_ui() else f"• {label}", *rest)
        table_utils.render_table(
            ["Device", "State", "Android", "Battery", "Wi-Fi", "Root"],
            rows,
            padding=3,
            accent_first_column=True,
        )

    # ADB warnings
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


__all__ = [
    "build_device_summaries",
    "print_dashboard",
    "resolve_active_device",
    # Exposed for tests
    "_connection_badge",
    "_status_badge",
    "_device_table_rows",
    "_no_device_line",
]
