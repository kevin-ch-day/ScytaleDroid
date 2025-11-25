"""Android Devices hub – list devices, pick active, then jump to per-device dashboard."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Dict, List, Optional

from scytaledroid.Utils.DisplayUtils import (
    display_settings,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.DeviceAnalysis.services.models import InventoryStatus


def _inventory_badge(status: InventoryStatus | None) -> str:
    if status is None or status.last_run_ts is None:
        return "NO SNAPSHOT"
    count_text = (
        f"{status.package_count} pkg" if status.package_count is not None else "unknown"
    )
    return f"{status.status_label} ({status.age_display}) {count_text}"


def _render_header(adb_status: str, live_count: int, historical_count: int) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(text_blocks.headline(f"Android devices — {ts}", width=display_settings.default_width()))
    print(f"ADB: {adb_status}   Live devices: {live_count}   Historical devices: {historical_count}")
    print(status_messages.status("Context: Devices hub", level="info"))


def _render_live_devices(
    summaries: List[Dict[str, Optional[str]]],
    inventory_lookup: Dict[str, InventoryStatus],
) -> None:
    if not summaries:
        print(status_messages.status("No live devices detected. Plug in a device and refresh.", level="warn"))
        return

    rows: List[List[str]] = []
    for idx, summary in enumerate(summaries, start=1):
        label = summary.get("model") or summary.get("device") or summary.get("serial") or "Unknown device"
        serial = summary.get("serial") or "—"
        oem = summary.get("manufacturer") or summary.get("brand") or ""
        android = summary.get("android_release") or summary.get("android_version") or "Unknown"
        state = summary.get("state") or "Unknown"
        rooted = summary.get("is_rooted") or "Unknown"
        inv_badge = _inventory_badge(inventory_lookup.get(serial))
        rows.append(
            [
                str(idx),
                f"{label} ({serial})",
                oem or "—",
                state.upper(),
                android,
                rooted,
                inv_badge,
            ]
        )

    table_kwargs = display_settings.apply_table_defaults(
        {"compact": True, "accent_first_column": False}
    )
    table_utils.render_table(
        ["#", "Device", "OEM", "State", "Android", "Root", "Inventory"],
        rows,
        **table_kwargs,
    )


def devices_hub() -> None:
    """List live devices, let the user pick one, then jump to the per-device dashboard."""

    while True:
        devices, warnings, summaries, serial_map = device_service.scan_devices()
        live_count = len(summaries)
        historical_count = 0  # placeholder for future DB-backed historical listing
        adb_status = "CONNECTED" if devices else "DISCONNECTED"
        inv_lookup: Dict[str, InventoryStatus] = {}
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

        print()
        _render_header(adb_status, live_count, historical_count)
        print()
        print(text_blocks.headline("Live devices", width=72))
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
        prompt_hint = "Select a device number to open its dashboard, or 0 to go back to main."
        print(prompt_hint)
        print(status_messages.status("Shortcuts: r=Refresh  q/0=Back", level="info"))
        choice_keys = [str(idx) for idx in range(1, len(summaries) + 1)]
        default_choice = "0" if len(summaries) == 0 else ("0" if len(summaries) == 1 else "1")
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
        from scytaledroid.DeviceAnalysis.device_analysis_menu import device_menu

        device_menu()
        # loop back to hub to allow switching


__all__ = ["devices_hub"]
