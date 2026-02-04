"""DeviceAnalysis menu - renders dashboard and routes device actions."""

from __future__ import annotations

from typing import Dict, Optional

from datetime import datetime
from scytaledroid.Utils.DisplayUtils import colors, prompt_utils, status_messages, text_blocks
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import INVENTORY_STALE_SECONDS

from scytaledroid.DeviceAnalysis.services import device_service
from .device_menu import (
    handle_choice,
)
from .device_menu.auto_ops import (
    ensure_active_device as auto_connect_device,
    ensure_inventory_survey,
)
from .device_menu.actions import _connect_to_device  # reuse existing picker UI


EXIT_TO_MAIN = "main"
EXIT_TO_HUB = "hub"


def device_menu(return_to: str = EXIT_TO_MAIN) -> str:
    """Render the Device Analysis menu until the user chooses to go back."""
    from scytaledroid.Database.db_utils import schema_gate
    ok, message, detail = schema_gate.inventory_schema_gate()
    if not ok:
        status_messages.print_status(f"[ERROR] {message}", level="error")
        if detail:
            status_messages.print_status(detail, level="error")
        status_messages.print_status(
            "Fix: Database Tools → Apply Tier-1 schema migrations (or import canonical DB export), then retry.",
            level="error",
        )
        return return_to

    summary_cache: Dict[str, Dict[str, Optional[str]]] = {}
    surveyed_serials: set[str] = set()

    while True:
        devices, warnings, summaries, serial_map = device_service.scan_devices()
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

        _render_dashboard(active_details, inventory_metadata)

        if warnings and not devices:
            # No devices / adb unavailable; prompt and continue loop
            prompt_utils.press_enter_to_continue()
            continue

        for message in auto_messages:
            print(message, flush=True)

        if not active_device and len(devices) > 1:
            print(
                status_messages.status(
                    "Multiple devices detected. Use option 9 to select the target device.",
                    level="info",
                ),
                flush=True,
            )

        print()
        print("Select action:")

        ensure_inventory_survey(
            active_serial,
            metadata=inventory_metadata,
            surveyed_serials=surveyed_serials,
            emit=lambda msg: print(msg, flush=True),
        )

        valid_keys = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
        default_choice = "9" if not active_device else "1"
        choice = prompt_utils.get_choice(valid_keys + ["0"], default=default_choice)

        if choice == "0":
            return return_to

        handle_choice(
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


def _render_dashboard(
    active_details: Optional[Dict[str, Optional[str]]],
    inventory_metadata: Optional[object],
) -> None:
    from scytaledroid.DeviceAnalysis.device_menu.formatters import (
        format_timestamp_utc,
        prettify_model,
    )

    print()
    print(text_blocks.headline("Device Dashboard", width=70))

    adb_state = "Connected" if active_details else "Disconnected"
    root_state = "unknown"
    serial = None
    model_label = "Unknown"
    if active_details:
        serial = active_details.get("serial") or None
        model_label = prettify_model(active_details.get("model") or active_details.get("device"))
        root_raw = (active_details.get("is_rooted") or "").strip().upper()
        if root_raw == "YES":
            root_state = "root"
        elif root_raw == "NO":
            root_state = "non-root"

    device_label = model_label if model_label != "Unknown" else "—"
    serial_label = serial or "—"
    adb_label = f"{adb_state} · {root_state}"

    status_messages.print_strip(
        "Device",
        [
            ("Model", device_label),
            ("Serial", serial_label),
            ("ADB", adb_label),
        ],
        width=70,
    )

    print()
    print(text_blocks.headline("Inventory", width=70))
    status = inventory_metadata
    if not active_details:
        print(status_messages.status("No active device. Use option 9 to select one.", level="warn"))
    elif status is None:
        print(status_messages.status("Inventory: not yet run. Use option 1 to sync.", level="warn"))
    else:
        status_label = getattr(status, "status_label", None) or "unknown"
        age = getattr(status, "age_display", "unknown")
        pkg_count = getattr(status, "package_count", None)
        last_ts = getattr(status, "last_run_ts", None)
        if isinstance(status, dict) and not last_ts:
            ts_val = status.get("timestamp")
            if isinstance(ts_val, datetime):
                last_ts = ts_val

        threshold_label = (
            f"{INVENTORY_STALE_SECONDS // 3600}h"
            if INVENTORY_STALE_SECONDS >= 3600
            else f"{INVENTORY_STALE_SECONDS // 60}m"
        )

        status_messages.print_strip(
            "Inventory snapshot",
            [
                ("Status", str(status_label).upper()),
                ("Packages", pkg_count or "—"),
                ("Last sync", format_timestamp_utc(last_ts) if last_ts else "—"),
                ("Age", age),
                ("Threshold", threshold_label),
            ],
            width=70,
        )

        if str(status_label).upper() == "NONE":
            print(status_messages.status("No inventory snapshot found. Run a full sync to capture the current app state.", level="warn"))

    print()
    print("1) Inventory & database sync")
    print("2) Pull APKs for static analysis")
    print("3) Detailed device report")
    print("4) Logcat")
    print("5) Open ADB shell")
    print("6) Export device dossier")
    print("7) Manage harvest watchlists")
    print("8) Open APK library (filtered)")
    print("9) Switch device")
    print("0) Back")
