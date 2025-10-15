"""DeviceAnalysis menu - renders dashboard and routes device actions."""

from __future__ import annotations

import time
from typing import Dict, Optional

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import adb_utils
from .device_menu import (
    build_device_summaries,
    build_main_menu_options,
    handle_choice,
    print_dashboard,
    resolve_active_device,
)


def device_menu() -> None:
    """Render the Device Analysis menu until the user chooses to go back."""
    summary_cache: Dict[str, Dict[str, Optional[str]]] = {}

    while True:
        devices, warnings = adb_utils.scan_devices()
        last_refresh_ts = time.time()
        active_device = resolve_active_device(devices)
        summaries, serial_map = build_device_summaries(devices, summary_cache)

        active_details = None
        if active_device:
            serial = active_device.get("serial")
            if serial:
                active_details = serial_map.get(serial)

        print_dashboard(
            summaries,
            active_details,
            warnings,
            last_refresh_ts,
            serial_map,
        )
        print()
        menu_utils.print_header("Device Analysis")
        options = build_main_menu_options(active_details)
        menu_utils.print_menu(options, is_main=False, default="1", exit_label="Back")
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
        for serial in list(summary_cache.keys()):
            if serial not in present_serials:
                summary_cache.pop(serial, None)
