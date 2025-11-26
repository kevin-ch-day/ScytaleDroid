"""Menu action handlers for the Device Analysis menu."""

from __future__ import annotations

from importlib import import_module
from typing import Dict, List, Optional

from scytaledroid.Utils.DisplayUtils import (
    error_panels,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from scytaledroid.DeviceAnalysis import adb_utils, device_manager
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
from scytaledroid.DeviceAnalysis.services import apk_library_service, device_service
from scytaledroid.DeviceAnalysis.services import info_service


_HELPER_ROUTES = {
    "5": ("inventory", "run_device_summary", True, "Collect detailed device summary"),
    "6": ("apk_pull", "pull_apks", True, "Pull APKs from the device"),
    "7": ("logcat", "stream_logcat", True, "Stream logcat output"),
    "8": ("shell", "open_shell", True, "Open interactive adb shell"),
    "10": ("report", "generate_device_report", True, "Export the device dossier"),
    "11": ("watchlist_manager", "manage_watchlists", False, "Manage harvest watchlists"),
}


def handle_choice(
    choice: str,
    devices: List[Dict[str, Optional[str]]],
    summaries: List[Dict[str, Optional[str]]],
    active_device: Optional[Dict[str, Optional[str]]],
    active_details: Optional[Dict[str, Optional[str]]],
) -> bool:
    if choice == "1":
        # Jump to the full devices hub for consistent list/switch UX.
        from scytaledroid.DeviceAnalysis.device_hub_menu import devices_hub

        devices_hub()
    elif choice == "2":
        _connect_to_device(devices, summaries)
    elif choice == "3":
        _show_device_info(active_device, active_details)
    elif choice == "4":
        serial = active_device.get("serial") if active_device else device_manager.get_active_serial()
        if not serial:
            error_panels.print_error_panel(
                "Inventory & database sync",
                "No active device. Connect first to sync.",
            )
            prompt_utils.press_enter_to_continue()
            return False
        # Use service façade for sync (CLI path)
        from scytaledroid.DeviceAnalysis.services import inventory_service
        from .formatters import format_device_line

        try:
            label = format_device_line(active_details or {"serial": serial}, include_release=True)
            if label:
                print(text_blocks.headline(f"Inventory & database sync — {label}", width=70))
            inventory_service.run_full_sync(serial, ui_prefs=None, progress_sink="cli")
        except inventory_service.InventoryServiceError as exc:
            error_panels.print_error_panel(
                "Inventory & database sync",
                str(exc),
            )
            prompt_utils.press_enter_to_continue()
    elif choice == "5":
        _forward_to_helper(choice, active_device)
    elif choice == "6":
        _run_apk_pull(active_device)
    elif choice in {"7", "8", "10", "11"}:
        _forward_to_helper(choice, active_device)
    elif choice == "9":
        _disconnect_device()
    elif choice == "12":
        _open_apk_library_filtered(active_device)
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
) -> List[menu_utils.MenuOption]:
    serial = active_details.get("serial") if active_details else device_manager.get_active_serial()
    has_device = bool(serial)

    inv_status_obj = device_service.fetch_inventory_metadata(serial) if serial else None
    inventory_status = format_inventory_status(serial)
    pull_hint = format_pull_hint(serial)

    # Derive compact badges from status strings
    inv_badge: Optional[str] = None
    if inv_status_obj:
        if inv_status_obj.is_stale:
            inv_badge = "recommended"
        elif inv_status_obj.status_label == "NONE":
            inv_badge = "not run"

    pull_badge: Optional[str] = None

    needs_active = None if has_device else "needs active"

    options: List[menu_utils.MenuOption] = [
        menu_utils.MenuOption("1", "Open devices hub"),
        menu_utils.MenuOption("2", "Connect to a device"),
        menu_utils.MenuOption(
            "3",
            "Device info",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "4",
            "Inventory & database sync (full)",
            badge=inv_badge or needs_active,
            hint="Refresh all packages and DB entries",
        ),
        menu_utils.MenuOption(
            "5",
            "Detailed device report",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "6",
            "Pull APKs",
            disabled=not has_device,
            badge=pull_badge or needs_active,
            hint="Fetch APKs to data/apks for static analysis",
        ),
        menu_utils.MenuOption(
            "7",
            "Logcat",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "8",
            "Open ADB shell",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption(
            "9",
            "Disconnect device",
            disabled=not has_device,
            badge=needs_active,
        ),
        menu_utils.MenuOption("10", "Export device dossier", disabled=not has_device, badge=needs_active),
        menu_utils.MenuOption("11", "Manage harvest watchlists"),
        menu_utils.MenuOption("12", "Open APK library (filtered)"),
    ]

    return options


def _list_devices(summaries: List[Dict[str, Optional[str]]]) -> None:
    # Instead of an inline list + extra prompt, jump to the full devices hub.
    from scytaledroid.DeviceAnalysis.device_hub_menu import devices_hub

    devices_hub()


def _connect_to_device(
    devices: List[Dict[str, Optional[str]]],
    summaries: List[Dict[str, Optional[str]]],
) -> None:
    if not devices:
        error_panels.print_info_panel(
            "Connect to Device",
            "No devices detected by adb.",
            hint="Attach a device and ensure adb recognizes it (adb devices).",
        )
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Select Device", subtitle="Available adb devices")
    numbered_devices = {str(idx): summary for idx, summary in enumerate(summaries, start=1)}
    options = []
    for idx, summary in numbered_devices.items():
        label = format_device_line(summary, include_release=True)
        description = format_battery(summary)
        options.append(menu_utils.MenuOption(str(idx), label, description=description))
    menu_utils.print_menu(options)

    choice = prompt_utils.get_choice(list(numbered_devices.keys()) + ["0"], default="1")
    if choice == "0":
        return

    summary = numbered_devices[choice]
    serial = summary.get("serial")
    if not serial:
        error_panels.print_warning_panel(
            "Connect to Device",
            "Selected device has no serial identifier.",
        )
        prompt_utils.press_enter_to_continue()
        return

    from scytaledroid.DeviceAnalysis.services import device_service

    if device_service.set_active_serial(serial):
        label = format_device_line(summary, include_release=True)
        print(f"\nActive device set to {label}.")
        log.info(f"Active device set to {serial}.", category="device")
    else:
        error_panels.print_warning_panel(
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
    info_rows = info_service.fetch_device_info(active_details)
    if not info_rows:
        error_panels.print_error_panel(
            "Device Info",
            "No active device. Use option 3 to connect first.",
        )
        prompt_utils.press_enter_to_continue()
        return

    print("\nDevice information:")
    table_utils.render_table(["Field", "Value"], [[field, value] for field, value in info_rows.items()])
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


def _open_apk_library_filtered(active_device: Optional[Dict[str, Optional[str]]]) -> None:
    serial = active_device.get("serial") if active_device else device_manager.get_active_serial()
    if not serial:
        print(status_messages.status("No active device. Select a device first.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        from scytaledroid.DeviceAnalysis.apk_library_menu import apk_library_menu

        apk_library_menu(device_filter=serial)
    except Exception as exc:
        log.error(f"Failed to open APK library for {serial}: {exc}", category="application")
        print(status_messages.status("Unable to open APK library. Check logs for details.", level="error"))
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

    status = device_service.fetch_inventory_metadata(serial)
    if status is None or status.status_label.upper() == "NONE":
        print("\nPull APKs")
        print("=========")
        print(status_messages.status("No inventory snapshot found. Run a full inventory & DB sync first.", level="warn"))
        from scytaledroid.DeviceAnalysis.services import inventory_service
        try:
            inventory_service.run_full_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
        except Exception as exc:
            print(status_messages.status(f"Inventory sync failed: {exc}", level="error"))
        return
    # Detect change vs snapshot (if metadata carries change flags) or age-based staleness
    changed = bool(getattr(status, "packages_changed", False) or getattr(status, "scope_changed", False))
    if status.is_stale:
        print("\nPull APKs")
        print("=========")
        print(
            status_messages.status(
                f"Current inventory: {status.status_label} ({status.age_display}) • {status.package_count or 'unknown'} packages",
                level="warn",
            )
        )
        print(
            status_messages.status(
                "Pulling APKs now may miss recently added or removed apps (stale by age).",
                level="warn",
            )
        )
        options = {
            "1": "Run inventory & database sync first (recommended)",
            "2": "Proceed with stale inventory",
            "0": "Cancel",
        }
        menu_utils.print_menu(options, show_exit=False, show_descriptions=False)
        choice = prompt_utils.get_choice(list(options) + ["0"], default="1")
        if choice == "0":
            return
        if choice == "1":
            from scytaledroid.DeviceAnalysis.services import inventory_service
            try:
                inventory_service.run_full_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
                status = device_service.fetch_inventory_metadata(serial)
            except Exception as exc:
                print(status_messages.status(f"Inventory sync failed: {exc}", level="error"))
                return
        # fall through to pull if choice == "2" or after sync
    elif changed:
        print("\nPull APKs")
        print("=========")
        print(
            status_messages.status(
                "Device packages changed since the last inventory snapshot.",
                level="info",
            )
        )
        print(
            status_messages.status(
                "Proceeding without sync may miss updated packages.",
                level="warn",
            )
        )
        options = {
            "1": "Run inventory & database sync now (recommended)",
            "2": "Use last snapshot anyway",
            "0": "Cancel",
        }
        menu_utils.print_menu(options, show_exit=False, show_descriptions=False)
        choice = prompt_utils.get_choice(list(options) + ["0"], default="1")
        if choice == "0":
            return
        if choice == "1":
            from scytaledroid.DeviceAnalysis.services import inventory_service
            try:
                inventory_service.run_full_sync(serial=serial, ui_prefs=text_blocks.UI_PREFS)
                status = device_service.fetch_inventory_metadata(serial)
            except Exception as exc:
                print(status_messages.status(f"Inventory sync failed: {exc}", level="error"))
                return

    if not ensure_recent_inventory(serial, device_context=active_device):
        return

    device_context = active_device or {"serial": serial}
    _forward_to_helper("6", device_context)


__all__ = ["handle_choice", "build_main_menu_options"]
