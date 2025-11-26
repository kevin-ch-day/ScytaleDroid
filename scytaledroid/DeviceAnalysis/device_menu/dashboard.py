"""Dashboard rendering helpers for the Device Analysis menu.

This module focuses on compact, badge-driven output that fits reliably
within narrow terminals and avoids multi-line hint panels. The dashboard
header is rendered as a single line with concise status tokens; detailed
cards are discoverable via menu actions rather than always-on panels.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
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
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import (
    INVENTORY_STALE_SECONDS,
)
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.utils import humanize_seconds
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


def _build_delta_items(delta: object, *, limit: int = 5) -> list[str]:
    """Format top-N added/removed/updated packages for display."""

    if not isinstance(delta, dict):
        return []

    palette = colors.get_palette()
    messages: list[str] = []

    added_list = delta.get("added") if isinstance(delta.get("added"), list) else []
    removed_list = delta.get("removed") if isinstance(delta.get("removed"), list) else []
    updated_list = delta.get("updated") if isinstance(delta.get("updated"), list) else []

    def _join_names(names: list[str]) -> str:
        if not names:
            return ""
        if len(names) > limit:
            names = names[:limit] + ["…"]
        return ", ".join(names)

    added_names = [name for name in added_list if isinstance(name, str) and name]
    if added_names:
        messages.append(
            colors.apply("Added: ", palette.success, bold=True)
            + _join_names(added_names)
        )

    removed_names = [name for name in removed_list if isinstance(name, str) and name]
    if removed_names:
        messages.append(
            colors.apply("Removed: ", palette.error, bold=True)
            + _join_names(removed_names)
        )

    if updated_list:
        formatted_updates: list[str] = []
        for entry in updated_list[:limit]:
            if not isinstance(entry, dict):
                continue
            pkg = entry.get("package") if isinstance(entry.get("package"), str) else None
            before = entry.get("before") if isinstance(entry.get("before"), str) else None
            after = entry.get("after") if isinstance(entry.get("after"), str) else None
            if not pkg:
                continue
            token = pkg
            if before or after:
                token = f"{pkg} ({before or '?'} → {after or '?'})"
            formatted_updates.append(token)
        if formatted_updates:
            if len(updated_list) > limit:
                formatted_updates.append("…")
            messages.append(
                colors.apply("Updated: ", palette.warning, bold=True)
                + ", ".join(formatted_updates)
            )

    return messages


def _render_inventory_status(metadata: object) -> None:
    """Render a compact inventory status block with delta hints."""

    # Accept both legacy dict metadata and InventoryStatus dataclass
    ts = None
    package_count = None
    stale = False
    age_text = None
    delta = {}
    if isinstance(metadata, dict):
        ts = metadata.get("timestamp")
        package_count = metadata.get("package_count")
        delta = metadata.get("package_delta_summary") or {}
    else:
        # InventoryStatus dataclass support
        ts = getattr(metadata, "last_run_ts", None)
        package_count = getattr(metadata, "package_count", None)
        stale = bool(getattr(metadata, "is_stale", False))
        age_text = getattr(metadata, "age_display", None)

    timestamp_display = "Unknown"
    if isinstance(ts, datetime):
        ts_utc = ts.astimezone(timezone.utc)
        timestamp_display = ts_utc.strftime("%Y-%m-%d %H:%M:%S %Z")
        if age_text is None:
            age_seconds = max(0, (datetime.now(timezone.utc) - ts_utc).total_seconds())
            age_text = humanize_seconds(age_seconds)
            stale = stale or age_seconds > INVENTORY_STALE_SECONDS

    count_text = f"{package_count} packages" if isinstance(package_count, int) else None

    if isinstance(delta, dict):
        added = delta.get("total_added", 0)
        removed = delta.get("total_removed", 0)
        updated = delta.get("total_updated", 0)
    else:
        added = removed = updated = 0
    has_changes = any(val for val in (added, removed, updated))

    palette = colors.get_palette()
    status_chip = _status_badge("STALE" if stale else "FRESH", "warning" if stale else "success")
    lines: List[str] = []
    lines.append(
        f"{status_chip} Last run: {timestamp_display}"
        + (f" ({age_text} ago)" if age_text else "")
    )
    if count_text:
        lines.append(colors.apply(f"Packages: {count_text}", palette.text, bold=True))
    if has_changes:
        changes = []
        if added:
            changes.append(colors.apply(f"+{added}", palette.success, bold=True))
        if removed:
            changes.append(colors.apply(f"-{removed}", palette.error, bold=True))
        if updated:
            changes.append(colors.apply(f"Δ{updated}", palette.warning, bold=True))
        lines.append(f"Changes since last inventory: {' / '.join(changes)}")
        lines.extend(_build_delta_items(delta))

    if not lines:
        return

    print()
    print(text_blocks.headline("Inventory status", width=74))
    for line in lines:
        print(line)


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
    *,
    show_device_table: bool = True,
    inventory_metadata: Optional[Dict[str, object]] = None,
    context: Optional[str] = None,
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
    if context:
        print(colors.apply(f"Context: {context}", colors.get_palette().hint))

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
    if show_device_table and summaries:
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

    # Inventory status / deltas for the active device
    if active_details and inventory_metadata:
        _render_inventory_status(inventory_metadata)

    # Device Analysis menu (sequential, no gaps)
    print()
    menu_utils.print_header("Device Analysis")
    options = [
        menu_utils.MenuOption(
            "1",
            "Open devices hub",
            description="List/switch devices in the Android devices hub",
        ),
        menu_utils.MenuOption("2", "Connect to a device"),
        menu_utils.MenuOption("3", "Device info"),
        menu_utils.MenuOption(
            "4",
            "Inventory & database sync (full)",
            hint="Refresh all packages and DB entries",
        ),
        menu_utils.MenuOption("5", "Detailed device report"),
        menu_utils.MenuOption(
            "6",
            "Pull APKs",
            hint="Fetch APKs to data/apks for static analysis",
        ),
        menu_utils.MenuOption("7", "Logcat"),
        menu_utils.MenuOption("8", "Open ADB shell"),
        menu_utils.MenuOption("9", "Disconnect device"),
        menu_utils.MenuOption("10", "Export device dossier"),
        menu_utils.MenuOption("11", "Manage harvest watchlists"),
        menu_utils.MenuOption("12", "Open APK library (filtered)"),
    ]
    spec = menu_utils.MenuSpec(
        items=options,
        default="1",
        exit_label="Back",
        show_exit=True,
        show_descriptions=True,
    )
    menu_utils.render_menu(spec)
    print("Shortcuts: r=Refresh  c=Connect/Switch  i=Info  s=Shell  l=Logcat  q/0=Back to main")

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
