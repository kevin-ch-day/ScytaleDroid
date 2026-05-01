"""Device Analysis menu entrypoint (canonical)."""

from __future__ import annotations

import time

from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .actions import build_main_menu_options, handle_choice
from .dashboard import print_dashboard


def device_menu(*, return_to: str = "main") -> str:
    """Main device menu loop; returns a routing token (e.g., 'main')."""

    summary_cache: dict[str, dict[str, str | None]] = {}
    last_refresh_ts: float | None = None

    while True:
        devices, warnings, summaries, serial_map = device_service.scan_devices(
            cache=summary_cache
        )
        last_refresh_ts = time.time()
        active_device = device_service.resolve_active_device(devices)
        active_details = None
        if active_device:
            active_details = serial_map.get(active_device.get("serial")) or active_device

        inventory_metadata = None
        if active_details and active_details.get("serial"):
            inventory_metadata = device_service.fetch_inventory_metadata(
                active_details.get("serial"),
                with_current_state=True,
            )

        print_dashboard(
            summaries=summaries,
            active_details=active_details,
            warnings=warnings,
            last_refresh_ts=last_refresh_ts,
            serial_map=serial_map,
            inventory_metadata=inventory_metadata,
            context=None,
        )

        option_keys = [opt.key for opt in build_main_menu_options(active_details)]
        choice = prompt_utils.get_choice(
            option_keys + ["0", "q", "r"],
            default="0",
            casefold=True,
        )
        if choice in {"r"}:
            continue
        if choice in {"0", "q"}:
            return return_to

        try:
            handled = handle_choice(
                choice,
                devices=devices,
                summaries=summaries,
                active_device=active_device,
                active_details=active_details,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.warning(f"Device menu action failed: {exc}", category="device")
            print(status_messages.status(f"Action failed: {exc}", level="error"))
            prompt_utils.press_enter_to_continue()
            continue
        if handled:
            return return_to


__all__ = ["device_menu"]
