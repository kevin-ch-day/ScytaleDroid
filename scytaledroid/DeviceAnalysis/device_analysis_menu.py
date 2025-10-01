"""DeviceAnalysis menu - renders dashboard and routes device actions."""

from __future__ import annotations

from datetime import datetime, timezone
from importlib import import_module
import time
from typing import Dict, List, Optional, Tuple

from scytaledroid.Utils.DisplayUtils import (
    error_panels,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import adb_utils, device_manager
from .inventory import inventory_sync_menu
from . import inventory as inventory_module
from . import watchlist_manager

INVENTORY_STALE_SECONDS = 600


def device_menu() -> None:
    """Render the Device Analysis menu until the user chooses to go back."""
    summary_cache: Dict[str, Dict[str, Optional[str]]] = {}
    last_refresh_ts: Optional[float] = None
    while True:
        devices, warnings = adb_utils.scan_devices()
        last_refresh_ts = time.time()
        active_device = _resolve_active_device(devices)
        summaries, serial_map = _build_device_summaries(devices, summary_cache)
        active_details = None
        if active_device:
            serial = active_device.get("serial")
            if serial:
                active_details = serial_map.get(serial)

        _print_dashboard(
            devices,
            active_details,
            warnings,
            last_refresh_ts,
            serial_map,
        )
        menu_utils.print_header("Device Analysis")
        options = _build_main_menu_options(active_details)
        menu_utils.print_menu(options, is_main=False, default="1", exit_label="Back")
        choice = prompt_utils.get_choice(list(options.keys()) + ["0"], default="1")

        if choice == "0":
            return

        refresh_requested = _handle_choice(
            choice, devices, summaries, active_device, active_details
        )

        if refresh_requested:
            summary_cache.clear()
            log.info("Device summary cache invalidated by user refresh.", category="device")
            continue

        # Clean up cache entries for disconnected devices
        present_serials = {d.get("serial") for d in devices if d.get("serial")}
        for serial in list(summary_cache.keys()):
            if serial not in present_serials:
                summary_cache.pop(serial, None)


def _build_device_summaries(
    devices: List[Dict[str, Optional[str]]],
    summary_cache: Dict[str, Dict[str, Optional[str]]],
) -> Tuple[List[Dict[str, Optional[str]]], Dict[str, Dict[str, Optional[str]]]]:
    summaries: List[Dict[str, Optional[str]]] = []
    serial_map: Dict[str, Dict[str, Optional[str]]] = {}

    refresh_threshold = 60

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


def _print_dashboard(
    devices: List[Dict[str, Optional[str]]],
    active_details: Optional[Dict[str, Optional[str]]],
    warnings: List[str],
    last_refresh_ts: Optional[float],
    serial_map: Dict[str, Dict[str, Optional[str]]],
) -> None:
    devices_found = len(devices)
    connection_status = device_manager.get_connection_status() or "Unknown"

    refreshed = (
        datetime.fromtimestamp(last_refresh_ts).strftime("%Y-%m-%d %H:%M:%S")
        if last_refresh_ts
        else "Unknown"
    )

    print()
    menu_utils.print_header("Device Dashboard")
    menu_utils.print_metrics(
        [
            ("Refreshed", refreshed),
            ("Devices Detected", devices_found),
            ("Connection Status", connection_status),
        ]
    )
    print()

    if active_details:
        serial = active_details.get("serial") or "Unknown"
        headline = _format_device_line(active_details, include_release=True)
        print(status_messages.status(f"Active Device: {headline}", level="info"))
        snapshot_headers = ["Model", "Android", "Battery", "Wi-Fi", "Root"]
        snapshot_rows = [[
            _prettify_model(active_details.get("model") or active_details.get("device")),
            _format_android_release(active_details),
            _format_battery(active_details),
            _format_wifi_state(active_details.get("wifi_state")),
            active_details.get("is_rooted") or "Unknown",
        ]]
        print()
        table_utils.render_table(snapshot_headers, snapshot_rows)
        menu_utils.print_hint(f"Serial: {serial}")
    else:
        print(status_messages.status("No active device connected.", level="warn"))
        last_serial = device_manager.get_last_serial()
        if last_serial:
            last_summary = serial_map.get(last_serial)
            if last_summary:
                formatted = _format_device_line(last_summary, include_release=True)
                menu_utils.print_hint(f"Last Connection: {formatted}")
            else:
                menu_utils.print_hint(f"Last Connection: {last_serial}")
        if devices_found:
            menu_utils.print_hint("Use option 3 to connect. Press Enter to refresh.")
        else:
            menu_utils.print_hint(
                "Attach a device with USB debugging enabled, then press Enter to refresh."
            )

    if warnings:
        print()
    for warning in warnings:
        print(status_messages.status(warning, level="warn"))
        log.warning(warning, category="device")


def _resolve_active_device(devices: List[Dict[str, Optional[str]]]) -> Optional[Dict[str, Optional[str]]]:
    serial = device_manager.get_active_serial()
    if not serial:
        return None

    for device in devices:
        if device.get("serial") == serial:
            return device

    # Active device disappeared; disconnect so status stays in sync.
    device_manager.disconnect()
    return None


def _handle_choice(
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
            model = _prettify_model(summary.get("model") or summary.get("device"))
            android_version = _format_android_release(summary)
            device_type = summary.get("device_type") or "Unknown"
            battery = summary.get("battery_level") or "—"
            if summary.get("battery_status"):
                battery = f"{battery} ({summary['battery_status']})" if battery != "—" else summary["battery_status"]
            wifi_state = _format_wifi_state(summary.get("wifi_state"))
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
        label = _format_device_line(summary, include_release=True)
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
        label = _format_device_line(summary, include_release=True)
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
            ("Manufacturer", _prettify_manufacturer(properties.get("manufacturer") or properties.get("brand"))),
            ("Model", _prettify_model(properties.get("model") or properties.get("device"))),
            ("Android Version", _format_android_release(properties, include_sdk=True) or "Unknown"),
            ("SDK Level", properties.get("sdk_level") or "Unknown"),
            ("Hardware", properties.get("hardware") or "Unknown"),
            ("Product", properties.get("product") or "Unknown"),
            ("Build ID", properties.get("build_id") or "Unknown"),
            ("Build Tags", _format_build_tags(properties.get("build_tags"))),
            ("Chipset", properties.get("chipset") or "Unknown"),
            ("Battery", _format_battery(properties)),
            ("Wi-Fi", _format_wifi_state(properties.get("wifi_state"))),
            ("Root Access", properties.get("is_rooted") or "Unknown"),
            ("Emulator", _format_emulator_flag(properties.get("is_emulator_flag"))),
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


_HELPER_ROUTES = {
    "6": ("inventory", "run_device_summary", True, "Collect detailed device summary"),
    "7": ("apk_pull", "pull_apks", True, "Pull APKs from the device"),
    "8": ("logcat", "stream_logcat", True, "Stream logcat output"),
    "9": ("shell", "open_shell", True, "Open interactive adb shell"),
    "11": ("report", "generate_device_report", True, "Export the device dossier"),
    "12": ("watchlist_manager", "manage_watchlists", False, "Manage harvest watchlists"),
}


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


def _build_main_menu_options(
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
    options["5"] = f"Inventory & database sync ({_format_inventory_status(serial)})"
    options["7"] = f"Pull APKs ({_format_pull_hint(serial)})"

    if not serial:
        options["6"] += " (requires device)"
        options["7"] += ""
        options["8"] += " (requires device)"
        options["9"] += " (requires device)"
        options["11"] += " (requires device)"

    return options


def _run_apk_pull(active_device: Optional[Dict[str, Optional[str]]]) -> None:
    serial = active_device.get("serial") if active_device else device_manager.get_active_serial()
    if not serial:
        error_panels.print_error_panel(
            "Pull APKs",
            "No active device. Connect first to pull APKs.",
        )
        prompt_utils.press_enter_to_continue()
        return

    if not _ensure_recent_inventory(serial):
        return

    device_context = active_device or {"serial": serial}
    _forward_to_helper("7", device_context)


def _ensure_recent_inventory(serial: str) -> bool:
    metadata = _get_latest_inventory_metadata(serial)
    if metadata and metadata.get("timestamp"):
        age = (datetime.now(timezone.utc) - metadata["timestamp"]).total_seconds()
        if age <= INVENTORY_STALE_SECONDS:
            return True

    print(status_messages.status("Inventory snapshot is stale—refreshing before pull.", level="info"))
    inventory_module.run_inventory_sync(serial, interactive=False)
    return True


def _get_latest_inventory_metadata(serial: Optional[str]) -> Optional[Dict[str, object]]:
    if not serial:
        return None
    snapshot = inventory_module.load_latest_inventory(serial)
    if not snapshot:
        return None
    generated_at = snapshot.get("generated_at")
    package_count = snapshot.get("package_count")
    timestamp = None
    if isinstance(generated_at, str):
        try:
            timestamp = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        except ValueError:
            timestamp = None
    return {
        "timestamp": timestamp,
        "package_count": package_count,
    }


def _format_inventory_status(serial: Optional[str]) -> str:
    if not serial:
        return "connect device"
    metadata = _get_latest_inventory_metadata(serial)
    if not metadata or not metadata.get("timestamp"):
        return "not yet run"
    age_seconds = (datetime.now(timezone.utc) - metadata["timestamp"]).total_seconds()
    if age_seconds < 0:
        age_seconds = 0
    return f"synced { _humanize_seconds(age_seconds) } ago"


def _format_pull_hint(serial: Optional[str]) -> str:
    if not serial:
        return "requires device"
    metadata = _get_latest_inventory_metadata(serial)
    if not metadata or not metadata.get("timestamp"):
        return "needs inventory sync"
    count = metadata.get("package_count")
    if isinstance(count, int):
        return f"inventory ready ({count} packages)"
    if isinstance(count, str) and count.isdigit():
        return f"inventory ready ({int(count)} packages)"
    return f"inventory ready"


def _humanize_seconds(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _format_battery(properties: Dict[str, Optional[str]]) -> str:
    level = properties.get("battery_level")
    status = properties.get("battery_status")
    if level and status:
        if status.lower() in level.lower():
            return level
        return f"{level} ({status})"
    if level:
        return level
    if status:
        return status
    return "Unknown"


def _format_android_release(
    properties: Dict[str, Optional[str]],
    *,
    include_sdk: bool = False,
) -> str:
    if not properties:
        return "Unknown"

    release = properties.get("android_release")
    if release:
        cleaned = release.split(" (", 1)[0].strip()
        if include_sdk:
            return release
        return cleaned

    version = properties.get("android_version")
    sdk = properties.get("sdk_level")

    if version and include_sdk and sdk:
        return f"Android {version} (SDK {sdk})"
    if version:
        return f"Android {version}"
    if sdk:
        return f"SDK {sdk}"
    return "Unknown"


def _format_wifi_state(value: Optional[str]) -> str:
    if not value:
        return "Unknown"
    normalized = value.strip().lower()
    if normalized in {"1", "on", "enabled", "true"}:
        return "On"
    if normalized in {"0", "off", "disabled", "false"}:
        return "Off"
    return value


def _format_build_tags(value: Optional[str]) -> str:
    if not value:
        return "Unknown"
    spaced = value.replace(",", ", ")
    while ", ," in spaced:
        spaced = spaced.replace(", ,", ", ")
    return spaced.strip()


def _format_emulator_flag(value: Optional[str]) -> str:
    if not value:
        return "No"
    lowered = value.strip().lower()
    return "Yes" if lowered in {"1", "true", "yes"} else "No"


def _format_device_line(
    device: Dict[str, Optional[str]],
    *,
    include_release: bool = False,
) -> str:
    model = _prettify_model(device.get("model") or device.get("device"))
    serial = device.get("serial") or "Unknown"
    label = f"{model} ({serial})" if model != "Unknown" else serial
    extras: List[str] = []

    device_type = device.get("device_type")
    if device_type:
        extras.append(device_type)

    if include_release:
        release = _format_android_release(device)
        if release and release != "Unknown":
            extras.append(release)

    manufacturer = _prettify_manufacturer(device.get("manufacturer") or device.get("brand"))
    if manufacturer and manufacturer.lower() not in label.lower():
        extras.append(manufacturer)

    if extras:
        return f"{label} | {' | '.join(extras)}"
    return label


def _prettify_model(value: Optional[str]) -> str:
    if not value:
        return "Unknown"
    cleaned = (
        value.replace("___", " - ")
        .replace("__", " ")
        .replace("_", " ")
    )
    cleaned = " ".join(cleaned.split())
    return cleaned if cleaned else "Unknown"


def _prettify_manufacturer(value: Optional[str]) -> str:
    if not value:
        return "Unknown"
    cleaned = " ".join(value.replace("_", " ").split())
    return cleaned.title()
