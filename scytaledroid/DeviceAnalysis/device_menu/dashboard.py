"""Dashboard rendering helpers for the Device Analysis menu.

This module focuses on compact, badge-driven output that fits reliably
within narrow terminals and avoids multi-line hint panels. The dashboard
header is rendered as a single line with concise status tokens; detailed
cards are discoverable via menu actions rather than always-on panels.
"""

from __future__ import annotations

from datetime import UTC, datetime

from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import (
    INVENTORY_STALE_SECONDS,
)
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.utils import humanize_seconds
from scytaledroid.Utils.DisplayUtils import (
    colors,
    error_panels,
    menu_utils,
    table_utils,
    text_blocks,
)
from scytaledroid.Utils.DisplayUtils.terminal import use_ascii_ui
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .formatters import (
    format_android_release,
    format_battery,
    format_device_line,
    format_timestamp_utc,
    format_wifi_state,
    prettify_manufacturer,
    prettify_model,
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


def _connection_badge(status: str | None) -> str:
    """Colour-code the aggregate connection status."""

    normalised = (status or "Unknown").strip().upper()
    if normalised in {"CONNECTED", "DEVICE"}:
        tone = "success"
    elif normalised in {"DISCONNECTED", "OFFLINE"}:
        tone = "error"
    else:
        tone = "warning"
    return _status_badge(normalised, tone)


def _state_badge(state: str | None) -> str:
    """Colour-code individual device states."""

    normalised = (state or "unknown").strip().upper()
    if normalised in {"DEVICE", "ONLINE"}:
        normalised = "READY"
        tone = "success"
    elif normalised in {"UNAUTHORIZED", "RECOVERY", "SIDELOAD"}:
        tone = "warning"
    elif normalised in {"OFFLINE"}:
        tone = "error"
    else:
        tone = "info"
    return _status_badge(normalised, tone)


def _root_badge(root_state: str | None) -> str:
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
    active_line: str | None,
    width: int | None = None,
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


def _styled_value(value: str | None, *, highlight: bool = False) -> str:
    palette = colors.get_palette()
    text = value or "Unknown"
    if not value or value.strip().lower() == "unknown":
        return colors.apply("Unknown", palette.muted, bold=True)
    style = palette.accent if highlight else palette.text
    return colors.apply(text, style, bold=highlight)


def _active_device_brief(details: dict[str, str | None], *, width: int) -> str:
    """Return a concise active device line suitable for the header."""
    label = format_device_line(details, include_release=False)
    return text_blocks.truncate_visible(label, max(10, width // 3))


def _last_seen_brief(
    last_summary: dict[str, str | None | None], last_serial: str | None
) -> str | None:
    if last_summary:
        return format_device_line(last_summary, include_release=True)
    if last_serial:
        return last_serial
    return None


def _device_table_rows(
    summaries: list[dict[str, str | None]]
) -> list[tuple[str, str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str, str]] = []
    for summary in summaries:
        model = prettify_model(summary.get("model") or summary.get("device"))
        serial = summary.get("serial") or "Unknown"
        label = f"{model} ({serial})" if model != "Unknown" else serial
        device_type = summary.get("device_type")
        if device_type:
            label = f"{label} | {device_type}"
        oem = prettify_manufacturer(summary.get("manufacturer") or summary.get("brand"))
        android = format_android_release(summary)
        if android.startswith("Android "):
            android = android.replace("Android ", "", 1)
        battery = format_battery(summary)
        wifi = format_wifi_state(summary.get("wifi_state"))
        root_badge = _root_badge(summary.get("is_rooted"))
        rows.append((label, oem, android, battery, wifi, root_badge))
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
        ts_utc = ts.astimezone(UTC)
        timestamp_display = format_timestamp_utc(ts_utc)
        if age_text is None:
            age_seconds = max(0, (datetime.now(UTC) - ts_utc).total_seconds())
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
    lines: list[str] = []
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
    devices: list[dict[str, str | None]],
    summary_cache: dict[str, dict[str, str | None]],
    *,
    refresh_threshold: int = 60,
) -> tuple[list[dict[str, str | None]], dict[str, dict[str, str | None]]]:
    summaries, serial_map = device_service.build_device_summaries(
        devices,
        summary_cache,
        refresh_threshold=refresh_threshold,
    )
    log.info(
        f"Refreshed device dashboard: {len(summaries)} device(s) detected.",
        category="device",
    )
    return summaries, serial_map


def print_dashboard(
    summaries: list[dict[str, str | None]],
    active_details: dict[str, str | None | None],
    warnings: list[str],
    last_refresh_ts: float | None,
    serial_map: dict[str, dict[str, str | None]],
    *,
    show_device_table: bool = True,
    inventory_metadata: dict[str, object | None] = None,
    context: str | None = None,
) -> None:
    devices_found = len(summaries)
    print()

    # One-line guidance when disconnected
    if not active_details:
        last_serial = device_service.get_last_serial()
        last_summary = serial_map.get(last_serial) if last_serial else None
        last_seen = _last_seen_brief(last_summary, last_serial)
        line = _no_device_line(devices_found)
        if last_seen:
            line = f"{line} Last seen: {last_seen}"
        print(colors.apply(line, colors.get_palette().hint))

    # Device table (single row is fine)
    if show_device_table and summaries:
        rows = _device_table_rows(summaries)
        table_utils.render_table(
            ["Device", "OEM", "Android", "Battery", "Wi-Fi", "Root"],
            rows,
            padding=3,
            accent_first_column=True,
        )

    # Inventory status (inline)
    if active_details and inventory_metadata:
        status_label = str(getattr(inventory_metadata, "status_label", "UNKNOWN")).upper()
        age_display = getattr(inventory_metadata, "age_display", None) or "unknown"
        pkg_count = getattr(inventory_metadata, "package_count", None)
        pkg_text = f"{pkg_count}" if isinstance(pkg_count, int) else "—"
        print()
        print("Status")
        print("------" if use_ascii_ui() else "----------------------------")
        print(f"Inventory: {status_label}")
        print(f"Last sync: {age_display} ago")
        print(f"Device Packages: {pkg_text}")

    # Device Analysis menu (sequential, no gaps)
    print()
    menu_utils.print_header("Device Actions")
    from .actions import build_main_menu_options
    options = build_main_menu_options(active_details)
    default_choice = "1"
    if inventory_metadata:
        status_label = str(getattr(inventory_metadata, "status_label", "")).upper()
        if status_label == "FRESH":
            default_choice = "2"
    spec = menu_utils.MenuSpec(
        items=options,
        default=default_choice,
        exit_label="Back",
        show_exit=True,
        show_descriptions=True,
    )
    menu_utils.render_menu(spec)

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
    devices: list[dict[str, str | None]]
) -> dict[str, str | None | None]:
    return device_service.resolve_active_device(devices)


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
