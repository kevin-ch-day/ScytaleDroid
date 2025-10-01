"""Menu action handlers for the Device Analysis menu."""

from __future__ import annotations

from importlib import import_module
from typing import Dict, List, Optional

from scytaledroid.Utils.DisplayUtils import (
    error_panels,
    prompt_utils,
    table_utils,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .. import adb_utils, device_manager
from ..inventory import inventory_sync_menu
from .formatters import (
    format_android_release,
    format_build_tags,
    format_battery,
    format_device_line,
    format_emulator_flag,
    format_wifi_state,
    prettify_manufacturer,
    prettify_model,
)
from .inventory_guard import (
    ensure_recent_inventory,
    format_inventory_status,
    format_pull_hint,
)


_HELPER_ROUTES = {
    "6": ("inventory", "run_device_summary", True, "Collect detailed device summary"),
    "7": ("apk_pull", "pull_apks", True, "Pull APKs from the device"),
    "8": ("logcat", "stream_logcat", True, "Stream logcat output"),
    "9": ("shell", "open_shell", True, "Open interactive adb shell"),
    "11": ("report", "generate_device_report", True, "Export the device dossier"),
    "12": ("watchlist_manager", "manage_watchlists", False, "Manage harvest watchlists"),
}


def handle_choice(
    choice: str,
    devices: List[Dict[str, Optional[str]]],
    summaries: List[Dict[str, Optional[str]]],
    active_device: Optional[Dict[str, Optional[str]]],
    active_details: Optional[Dict[str, Optional[str]]],
) -> bool:
    if choice == "1":
        _list_devices(summaries)
    elif choice == "2":
        return True
    elif choice == "3":
        _connect_to_device(devices, summaries)
    elif choice == "4":
        _show_device_info(active_device, active_details)
    elif choice == "5":
        serial = active_device.get("serial") if active_device else device_manager.get_active_serial()
        inventory_sync_menu(serial)
    elif choice == "6":
        _forward_to_helper(choice, active_device)
    elif choice == "7":
        _run_apk_pull(active_device)
    elif choice == "10":
        _disconnect_device()
    elif choice in {"8", "9", "11", "12"}:
        _forward_to_helper(choice, active_device)
    else:
        error_panels.print_error_panel(
            "Device Analysis",
            f"Device option {choice} is not implemented yet.",
            hint="Track the roadmap for availability of this action.",
        )
        prompt_utils.press_enter_to_continue()

    return False


def build_main_menu_options(
    active_details: Optional[Dict[str, Optional[str]]]
) -> Dict[str, str]:
    options = {
        "1": "List devices",
        "2": "Refresh status",
        "3": "Connect to a device",
        "4": "Show device info",
        "5": "Inventory & database sync",
        "6": "Run detailed device report",
        "7": "Pull APKs",
        "8": "Logcat",
        "9": "Open ADB shell",
        "10": "Disconnect device",
        "11": "Export device dossier",
        "12": "Manage harvest watchlists",
    }

    serial = active_details.get("serial") if active_details else device_manager.get_active_serial()
    options["5"] = f"Inventory & database sync ({format_inventory_status(serial)})"
    options["7"] = f"Pull APKs ({format_pull_hint(serial)})"

    if not serial:
        options["6"] += " (requires device)"
        options["8"] += " (requires device)"
        options["9"] += " (requires device)"
        options["11"] += " (requires device)"

    return options


def _list_devices(summaries: List[Dict[str, Optional[str]]]) -> None:
    if not summaries:
        error_panels.print_error_panel(
            "Device List",
            "No Android devices detected.",
            hint="Ensure USB debugging is enabled and the device is connected.",
        )
    else:
        print("\nConnected devices:")
        headers = ["#", "Serial", "Model", "Android", "Type", "Battery", "Wi-Fi", "Root", "State"]
        rows: List[List[str]] = []
        for index, summary in enumerate(summaries, start=1):
            serial = summary.get("serial") or "—"
            model = prettify_model(summary.get("model") or summary.get("device"))
            android_version = format_android_release(summary)
            device_type = summary.get("device_type") or "Unknown"
            battery = summary.get("battery_level") or "—"
            if summary.get("battery_status"):
                battery = (
                    f"{battery} ({summary['battery_status']})"
                    if battery != "—"
                    else summary["battery_status"]
                )
            wifi_state = format_wifi_state(summary.get("wifi_state"))
            root_state = summary.get("is_rooted") or "Unknown"
            state = summary.get("state") or "Unknown"
            rows.append(
                [
                    str(index),
                    serial,
                    model,
                    android_version,
                    device_type,
                    battery,
                    wifi_state,
                    root_state,
                    state,
                ]
            )
        table_utils.render_table(headers, rows)
    prompt_utils.press_enter_to_continue()


def _connect_to_device(
    devices: List[Dict[str, Optional[str]]],
    summaries: List[Dict[str, Optional[str]]],
) -> None:
    if not devices:
        error_panels.print_error_panel(
            "Connect to Device",
            "No devices available to connect.",
            hint="Attach a device and ensure adb recognizes it (adb devices).",
        )
        prompt_utils.press_enter_to_continue()
        return

    print("\nSelect a device to connect:")
    numbered_devices = {str(idx): summary for idx, summary in enumerate(summaries, start=1)}
    for idx, summary in numbered_devices.items():
        label = format_device_line(summary, include_release=True)
        print(f"{idx}) {label}")
    print("0) Cancel")

    choice = prompt_utils.get_choice(list(numbered_devices.keys()) + ["0"])
    if choice == "0":
        return

    summary = numbered_devices[choice]
    serial = summary.get("serial")
    if not serial:
        error_panels.print_error_panel(
            "Connect to Device",
            "Selected device has no serial identifier.",
        )
        prompt_utils.press_enter_to_continue()
        return

    if device_manager.set_active_device(serial):
        label = format_device_line(summary, include_release=True)
        print(f"\nActive device set to {label}.")
        log.info(f"Active device set to {serial}.", category="device")
    else:
        error_panels.print_error_panel(
            "Connect to Device",
            f"Failed to activate device with serial {serial}.",
            hint="Retry after verifying adb authorization on the device.",
        )
        log.warning(f"Failed to activate device {serial}.", category="device")
    prompt_utils.press_enter_to_continue()


def _show_device_info(
    active_device: Optional[Dict[str, Optional[str]]],
    active_details: Optional[Dict[str, Optional[str]]],
) -> None:
    if not active_device:
        error_panels.print_error_panel(
            "Device Info",
            "No active device. Use option 3 to connect first.",
        )
        prompt_utils.press_enter_to_continue()
        return

    serial = active_device.get("serial")
    if not serial:
        error_panels.print_error_panel(
            "Device Info",
            "Unable to determine the serial for the active device.",
        )
        prompt_utils.press_enter_to_continue()
        return

    properties = active_details or adb_utils.get_basic_properties(serial)
    if not properties:
        error_panels.print_error_panel(
            "Device Info",
            "No additional properties could be retrieved.",
            hint="Ensure the device is unlocked and responsive.",
        )
    else:
        print("\nDevice information:")
        info_rows = [
            ("Serial", serial),
            ("Device Type", properties.get("device_type", "Unknown")),
            (
                "Manufacturer",
                prettify_manufacturer(
                    properties.get("manufacturer") or properties.get("brand")
                ),
            ),
            ("Model", prettify_model(properties.get("model") or properties.get("device"))),
            (
                "Android Version",
                format_android_release(properties, include_sdk=True) or "Unknown",
            ),
            ("SDK Level", properties.get("sdk_level") or "Unknown"),
            ("Hardware", properties.get("hardware") or "Unknown"),
            ("Product", properties.get("product") or "Unknown"),
            ("Build ID", properties.get("build_id") or "Unknown"),
            ("Build Tags", format_build_tags(properties.get("build_tags"))),
            ("Chipset", properties.get("chipset") or "Unknown"),
            ("Battery", format_battery(properties)),
            ("Wi-Fi", format_wifi_state(properties.get("wifi_state"))),
            ("Root Access", properties.get("is_rooted") or "Unknown"),
            ("Emulator", format_emulator_flag(properties.get("is_emulator_flag"))),
        ]
        table_utils.render_table(["Field", "Value"], [[field, value] for field, value in info_rows])
    prompt_utils.press_enter_to_continue()


def _disconnect_device() -> None:
    if device_manager.get_active_serial():
        device_manager.disconnect()
        print("\nDevice disconnected.")
        log.info("Active device cleared by user.", category="device")
    else:
        print("\nNo active device to disconnect.")
        log.info("Disconnect request received but no active device was set.", category="device")
    prompt_utils.press_enter_to_continue()


def _forward_to_helper(option: str, active_device: Optional[Dict[str, Optional[str]]]) -> None:
    module_name, func_name, requires_device, description = _HELPER_ROUTES[option]

    if requires_device and not active_device:
        error_panels.print_error_panel(
            description,
            "This action requires an active device. Please connect first.",
        )
        prompt_utils.press_enter_to_continue()
        return

    try:
        module = import_module(f"scytaledroid.DeviceAnalysis.{module_name}")
    except ModuleNotFoundError:
        error_panels.print_error_panel(
            description,
            f"[{module_name}] helper not available yet.",
            hint="Check that the module has been implemented before running this option.",
        )
        prompt_utils.press_enter_to_continue()
        return

    handler = getattr(module, func_name, None)
    if not callable(handler):
        error_panels.print_error_panel(
            description,
            f"[{module_name}] is missing the '{func_name}' handler.",
        )
        prompt_utils.press_enter_to_continue()
        return

    serial = active_device.get("serial") if active_device else None
    handler(serial=serial)  # type: ignore[arg-type,call-arg]


def _run_apk_pull(active_device: Optional[Dict[str, Optional[str]]]) -> None:
    serial = active_device.get("serial") if active_device else device_manager.get_active_serial()
    if not serial:
        error_panels.print_error_panel(
            "Pull APKs",
            "No active device. Connect first to pull APKs.",
        )
        prompt_utils.press_enter_to_continue()
        return

    if not ensure_recent_inventory(serial, device_context=active_device):
        return

    device_context = active_device or {"serial": serial}
    _forward_to_helper("7", device_context)


__all__ = ["handle_choice", "build_main_menu_options"]
