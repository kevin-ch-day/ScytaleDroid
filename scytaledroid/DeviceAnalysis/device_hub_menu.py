"""Android Devices hub – list devices, pick active, then jump to per-device dashboard."""

from __future__ import annotations

from datetime import UTC, datetime

from scytaledroid.DeviceAnalysis.device_menu.formatters import format_timestamp_utc
from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.DeviceAnalysis.services.models import InventoryStatus
from scytaledroid.Utils.DisplayUtils import (
    colors,
    display_settings,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def _inventory_badge(status: InventoryStatus | None) -> str:
    if status is None or status.last_run_ts is None:
        return "NONE (no snapshot)"
    count_text = (
        f"{status.package_count} pkg" if status.package_count is not None else "unknown"
    )
    return f"{status.status_label} ({status.age_display}) {count_text}"


def _render_header(adb_status: str, live_count: int) -> None:
    ts = format_timestamp_utc(datetime.now(UTC))
    menu_utils.print_header("Device Inventory & Harvest")
    menu_utils.print_hint(
        "Select an attached device to open the compact operator dashboard for inventory, harvest, and evidence state."
    )
    menu_utils.print_section("Hub State")
    menu_utils.print_metrics(
        [
            ("UTC", ts),
            ("ADB", adb_status),
            ("Live devices", live_count),
        ]
    )


def _render_live_devices(
    summaries: list[dict[str, str | None]],
    inventory_lookup: dict[str, InventoryStatus],
) -> None:
    if not summaries:
        print(status_messages.status("No live devices detected. Plug in a device and refresh.", level="warn"))
        return

    rows: list[list[str]] = []
    palette = colors.get_palette()
    use_color = colors.colors_enabled()
    for idx, summary in enumerate(summaries, start=1):
        label = summary.get("model") or summary.get("device") or "Unknown device"
        serial = summary.get("serial") or "—"
        oem = summary.get("manufacturer") or summary.get("brand") or ""
        android_release = summary.get("android_release") or summary.get("android_version") or "Unknown"
        android_sdk = summary.get("android_sdk") or summary.get("sdk") or None
        android = f"{android_release} (SDK {android_sdk})" if android_sdk else android_release
        rooted_raw = summary.get("is_rooted") or "Unknown"
        rooted_value = str(rooted_raw).strip().upper()
        if rooted_value == "YES":
            rooted = "Yes"
            if use_color:
                rooted = colors.apply(rooted, palette.success, bold=True)
        elif rooted_value == "NO":
            rooted = "No"
            if use_color:
                rooted = colors.apply(rooted, palette.info, bold=True)
        else:
            rooted = "Unknown"
            if use_color:
                rooted = colors.apply(rooted, palette.muted)
        inv = inventory_lookup.get(serial)
        inv_age = inv.age_display if inv and inv.age_display else "—"
        inv_pkgs = str(inv.package_count) if inv and inv.package_count is not None else "—"
        rows.append(
            [
                str(idx),
                label,
                oem or "—",
                android,
                rooted,
                inv_age,
                inv_pkgs,
            ]
        )

    table_kwargs = display_settings.apply_table_defaults(
        {"compact": True, "accent_first_column": False, "zebra": True}
    )
    table_utils.render_table(
        ["#", "Device", "OEM", "Android", "Root", "Inv age", "Pkgs"],
        rows,
        column_styles=["muted", "accent", "muted", "text", None, "muted", "muted"],
        alignments=["right", "left", "left", "left", "left", "right", "right"],
        **table_kwargs,
    )


def devices_hub() -> None:
    """List live devices, let the user pick one, then jump to the per-device dashboard."""

    while True:
        devices, warnings, summaries, serial_map = device_service.scan_devices()
        live_count = len(summaries)
        adb_status = "CONNECTED" if devices else "DISCONNECTED"
        inv_lookup: dict[str, InventoryStatus] = {}
        for summary in summaries:
            serial = summary.get("serial")
            if serial:
                inv_lookup[serial] = device_service.fetch_inventory_metadata(serial) or InventoryStatus(
                    last_run_ts=None,
                    package_count=None,
                    age_seconds=None,
                    is_stale=False,
                    status_label="NO SNAPSHOT",
                    age_display="unknown",
                )

        if live_count == 1:
            chosen = summaries[0]
            serial = chosen.get("serial")
            if serial and device_service.set_active_serial(serial):
                log.info(f"Auto-selected active device {serial}", category="device")
                from scytaledroid.DeviceAnalysis.device_menu import device_menu

                result = device_menu(return_to="main")
                if str(result).lower() == "main":
                    return
                continue

        print()
        _render_header(adb_status, live_count)
        menu_utils.print_section("Devices")
        _render_live_devices(summaries, inv_lookup)

        if warnings:
            print()
            for warning in warnings:
                print(status_messages.status(warning, level="warn"))
            if not devices:
                # ADB unavailable or no devices; don't prompt for selection
                prompt_utils.press_enter_to_continue()
                continue

        print()
        hint = "Hint: select a device number, or use 0/q to return."
        if colors.colors_enabled():
            hint = colors.apply(hint, colors.get_palette().muted)
        print(hint)
        print("Select device:")
        choice_keys = [str(idx) for idx in range(1, len(summaries) + 1)]
        default_choice = "0" if len(summaries) == 0 else ("1" if len(summaries) == 1 else "1")
        choice = prompt_utils.get_choice(
            choice_keys + ["0", "q"],
            default=default_choice,
            casefold=True,
        )

        if choice in {"0", "q"}:
            break

        try:
            index = int(choice) - 1
        except ValueError:
            print(status_messages.status("Invalid selection.", level="warn"))
            continue

        if index < 0 or index >= len(summaries):
            print(status_messages.status("Selection out of range.", level="warn"))
            continue

        chosen = summaries[index]
        serial = chosen.get("serial")
        if not serial:
            print(status_messages.status("Unable to determine device serial.", level="error"))
            continue

        if not device_service.set_active_serial(serial):
            print(status_messages.status(f"Device {serial} is not available.", level="warn"))
            continue

        log.info(f"User selected active device {serial}", category="device")
        from scytaledroid.DeviceAnalysis.device_menu import device_menu

        result = device_menu(return_to="main")
        if str(result).lower() == "main":
            return
        # loop back to hub to allow switching


__all__ = ["devices_hub"]
