"""Shared device selection helper for dynamic analysis flows."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.adb import devices as adb_devices
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def select_device() -> tuple[str, str] | None:
    menu_utils.print_header("Dynamic Run Device")
    devices, warnings = adb_devices.scan_devices()
    for warning in warnings:
        print(status_messages.status(warning, level="warn"))
    if not devices:
        print(status_messages.status("No devices detected via adb.", level="error"))
        prompt_utils.press_enter_to_continue()
        return None

    device_options = [
        menu_utils.MenuOption(str(index + 1), adb_devices.get_device_label(device))
        for index, device in enumerate(devices)
    ]
    device_spec = menu_utils.MenuSpec(items=device_options, exit_label="Cancel", show_exit=True)
    menu_utils.render_menu(device_spec)
    device_choice = prompt_utils.get_choice(
        menu_utils.selectable_keys(device_options, include_exit=True),
        default="1",
        disabled=[option.key for option in device_options if option.disabled],
    )
    if device_choice == "0":
        return None
    device_index = int(device_choice) - 1
    device_serial = devices[device_index].get("serial")
    if not device_serial:
        print(status_messages.status("Selected device missing serial.", level="error"))
        prompt_utils.press_enter_to_continue()
        return None

    device_label = adb_devices.get_device_label(devices[device_index])
    return device_serial, device_label


__all__ = ["select_device"]
