"""DeviceAnalysis menu - renders dashboard and routes device actions."""

from __future__ import annotations

import time
from typing import Dict, Optional

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import adb_utils
from .device_menu import (
    build_device_summaries,
    build_main_menu_options,
    handle_choice,
    print_dashboard,
    resolve_active_device,
)
from .device_menu.auto_ops import (
    ensure_active_device as auto_connect_device,
    ensure_inventory_survey,
)
from .device_menu.inventory_guard.metadata import get_latest_inventory_metadata


def device_menu() -> None:
    """Render the Device Analysis menu until the user chooses to go back."""
    summary_cache: Dict[str, Dict[str, Optional[str]]] = {}
    surveyed_serials: set[str] = set()

    while True:
        devices, warnings = adb_utils.scan_devices()
        last_refresh_ts = time.time()
        active_device = resolve_active_device(devices)
        active_device, auto_messages = auto_connect_device(devices, active_device)

        summaries, serial_map = build_device_summaries(devices, summary_cache)

        active_serial = active_device.get("serial") if active_device else None
        active_details = serial_map.get(active_serial) if active_serial else None
        inventory_metadata = (
            get_latest_inventory_metadata(active_serial) if active_serial else None
        )

        print_dashboard(
            summaries,
            active_details,
            warnings,
            last_refresh_ts,
            serial_map,
        )

        for message in auto_messages:
            print(message, flush=True)

        if not active_device and len(devices) > 1:
            print(
                status_messages.status(
                    "Multiple devices detected. Use option 3 to select the target device.",
                    level="info",
                ),
                flush=True,
            )

        print()
        menu_utils.print_header("Device Analysis")
        options = build_main_menu_options(active_details)
        # Default to Connect when exactly one device is present
        default_key = "3" if len(summaries) == 1 else "1"
        menu_utils.print_menu(options, is_main=False, default=default_key, exit_label="Back")
        # Footer shortcuts (informational)
        print(
            "Shortcuts: r=Refresh  c=Connect/Switch  i=Info  s=Shell  l=Logcat  q/0=Back"
        )

        ensure_inventory_survey(
            active_serial,
            metadata=inventory_metadata,
            surveyed_serials=surveyed_serials,
            emit=lambda msg: print(msg, flush=True),
        )
        valid_keys = [option.key for option in options]
        choice = prompt_utils.get_choice(valid_keys + ["0"], default="1")

        if choice == "0":
            return

        refresh_requested = handle_choice(
            choice,
            devices,
            summaries,
            active_device,
            active_details,
        )

        if refresh_requested:
            summary_cache.clear()
            log.info(
                "Device summary cache invalidated by user refresh.",
                category="device",
            )
            continue

        present_serials = {d.get("serial") for d in devices if d.get("serial")}
        surveyed_serials.intersection_update(present_serials)
        for serial in list(summary_cache.keys()):
            if serial not in present_serials:
                summary_cache.pop(serial, None)
