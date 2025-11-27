"""DeviceAnalysis menu - renders dashboard and routes device actions."""

from __future__ import annotations

import time
from typing import Dict, Optional

from datetime import datetime
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils import text_blocks, table_utils, colors
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import INVENTORY_STALE_SECONDS
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import adb_utils
from scytaledroid.DeviceAnalysis.services import device_service
from .device_menu import (
    build_device_summaries,
    build_main_menu_options,
    handle_choice,
    print_dashboard,
)
from .device_menu.auto_ops import (
    ensure_active_device as auto_connect_device,
    ensure_inventory_survey,
)
from .device_menu.actions import _connect_to_device  # reuse existing picker UI
from .device_menu.inventory_guard.metadata import get_latest_inventory_metadata


EXIT_TO_MAIN = "main"
EXIT_TO_HUB = "hub"


def device_menu(return_to: str = EXIT_TO_MAIN) -> str:
    """Render the Device Analysis menu until the user chooses to go back."""
    summary_cache: Dict[str, Dict[str, Optional[str]]] = {}
    surveyed_serials: set[str] = set()

    while True:
        devices, warnings, summaries, serial_map = device_service.scan_devices()
        last_refresh_ts = time.time()
        active_device = device_service.resolve_active_device(devices)
        active_device, auto_messages = auto_connect_device(devices, active_device)

        active_serial = active_device.get("serial") if active_device else None
        active_details = serial_map.get(active_serial) if active_serial else None
        inventory_metadata = (
            device_service.fetch_inventory_metadata(active_serial, with_current_state=True) if active_serial else None
        )

        # If no active device but devices are present, offer an immediate connect prompt
        if not active_device and devices:
            should_connect = prompt_utils.prompt_yes_no(
                "Select a device now?",
                default=len(devices) == 1,
            )
            if should_connect:
                _connect_to_device(devices, summaries)
                # Restart loop to refresh dashboard with the chosen device
                summary_cache.clear()
                continue

        _render_status_panel(active_details, inventory_metadata)

        if warnings and not devices:
            # No devices / adb unavailable; prompt and continue loop
            prompt_utils.press_enter_to_continue()
            continue

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
        # Default to List devices to give a quick view before deeper actions
        default_key = "1"
        spec = menu_utils.MenuSpec(
            items=options,
            default=default_key,
            exit_label="Back",
            show_exit=True,
            show_descriptions=True,
        )
        menu_utils.render_menu(spec)
        # Footer shortcuts (informational)
        print(
            "Shortcuts: r=Refresh  c=Connect/Switch  i=Info  s=Shell  l=Logcat  q/0=Back to main"
        )

        ensure_inventory_survey(
            active_serial,
            metadata=inventory_metadata,
            surveyed_serials=surveyed_serials,
            emit=lambda msg: print(msg, flush=True),
        )
        valid_keys = [option.key for option in options]
        # Support shortcuts: r=refresh (redraw), q=back, c=connect, i=info, s=shell, l=logcat
        choice = prompt_utils.get_choice(valid_keys + ["0", "r", "q", "c", "i", "s", "l"], default="1")

        if choice in {"0", "q"}:
            return return_to
        if choice == "r":
            # Redraw dashboard without triggering sync
            continue
        if choice == "c":
            _connect_to_device(devices, summaries)
            summary_cache.clear()
            continue
        if choice == "i":
            _show_device_info(active_device, active_details)
            continue
        if choice == "s":
            handle_choice("8", devices, summaries, active_device, active_details)
            continue
        if choice == "l":
            handle_choice("7", devices, summaries, active_device, active_details)
            continue

        refresh_requested = handle_choice(
            choice,
            devices,
            summaries,
            active_device,
            active_details,
        )

        present_serials = {d.get("serial") for d in devices if d.get("serial")}
        surveyed_serials.intersection_update(present_serials)
        for serial in list(summary_cache.keys()):
            if serial not in present_serials:
                summary_cache.pop(serial, None)


def _render_status_panel(
    active_details: Optional[Dict[str, Optional[str]]],
    inventory_metadata: Optional[object],
) -> None:
    print()
    # Header context
    serial = active_details.get("serial") if active_details else None
    label = None
    if active_details:
        label = active_details.get("model") or active_details.get("device")
    heading = "Device dashboard"
    if label and serial:
        heading = f"Device dashboard — {label} ({serial})"
    menu_utils.print_header(heading)

    if not active_details:
        print(status_messages.status("No active device. Use Connect to select one.", level="warn"))
        return

    # Inventory status panel
    status = inventory_metadata
    if status is None:
        print(status_messages.status("Inventory: not yet run. Use option 4 to sync.", level="warn"))
        return

    # Normalize InventoryStatus fields and optional delta info
    status_label = getattr(status, "status_label", None) or "unknown"
    age = getattr(status, "age_display", "unknown")
    pkg_count = getattr(status, "package_count", None)
    is_stale = bool(getattr(status, "is_stale", False))
    last_ts = getattr(status, "last_run_ts", None)
    delta = {}
    if isinstance(status, dict):
        delta = status.get("package_delta_summary") or {}
        if not last_ts:
            ts_val = status.get("timestamp")
            if isinstance(ts_val, datetime):
                last_ts = ts_val

    print("Inventory status")
    print("================")
    from scytaledroid.Utils.DisplayUtils.terminal import use_ascii_ui

    palette = colors.get_palette()
    bullet = "●" if not use_ascii_ui() else "*"
    label_style = palette.success if status_label.upper() == "FRESH" and not is_stale else palette.warning
    status_line = f"{bullet} {status_label.upper()}  • Age: {age}  • Packages: {pkg_count or '—'}"
    print(colors.apply(status_line, label_style, bold=True) if colors.colors_enabled() else status_line)
    if isinstance(last_ts, datetime):
        print(f"Last sync: {last_ts.strftime('%Y-%m-%d %H:%M:%S %Z') or last_ts.isoformat()}")
    threshold_label = f"{INVENTORY_STALE_SECONDS // 3600}h" if INVENTORY_STALE_SECONDS >= 3600 else f"{INVENTORY_STALE_SECONDS // 60}m"
    if status_label.upper() == "NONE":
        print(f"Staleness threshold: {threshold_label} (applies after the first snapshot)")
        print(status_messages.status("No inventory snapshot found. Run a full sync to capture the current app state.", level="warn"))
        return
    print(f"Staleness threshold: {threshold_label}")

    # Last inventory result (now driven by unified InventoryDelta if available)
    delta_obj = getattr(status, "delta", None)
    added = removed = updated = 0
    if delta_obj:
        added = int(getattr(delta_obj, "new_count", 0) or 0)
        removed = int(getattr(delta_obj, "removed_count", 0) or 0)
        updated = int(getattr(delta_obj, "updated_count", 0) or 0)
    elif isinstance(delta, dict):
        added = int(delta.get("total_added", 0) or 0)
        removed = int(delta.get("total_removed", 0) or 0)
        updated = int(delta.get("total_updated", 0) or 0)

    if added or removed or updated:
        tokens = []
        if added:
            tokens.append(f"{added} new")
        if removed:
            tokens.append(f"{removed} removed")
        if updated:
            tokens.append(f"{updated} updated")
        print(f"Last inventory result: {', '.join(tokens)}.")
    else:
        print("Last inventory result: identical to previous snapshot (baseline unchanged).")

    if is_stale:
        print(
            status_messages.status(
                "Recommendation: run Inventory & database sync before pulling APKs or static analysis.",
                level="warn",
            )
        )
    print()
