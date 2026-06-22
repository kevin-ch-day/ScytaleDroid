"""Shared device selection helper for dynamic analysis flows."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def _clean_text(value: str | None) -> str:
    return " ".join(str(value or "").replace("_", " ").split()).strip()


def _device_name(device: dict[str, str | None]) -> str:
    name = (
        device.get("model")
        or device.get("display_name")
        or device.get("device")
        or device.get("serial")
        or "Unknown device"
    )
    return _clean_text(name) or "Unknown device"


def _device_android_version(device: dict[str, str | None]) -> str:
    version = str(device.get("android_version") or "").strip()
    if version:
        return version
    release = str(device.get("android_release") or "").strip()
    if release.lower().startswith("android "):
        return release.split(" ", 1)[1].split(" ", 1)[0].strip() or "—"
    return "—"


def _device_kind(device: dict[str, str | None]) -> str:
    kind = str(device.get("device_type") or "").strip().lower()
    if kind == "emulator":
        return "emulator"
    if kind == "physical":
        return "physical"
    return "device"


def _device_status(device: dict[str, str | None], *, active_serial: str | None) -> str:
    serial = str(device.get("serial") or "").strip()
    if active_serial and serial == active_serial:
        return "current"
    state = str(device.get("state") or "").strip().lower()
    if state == "device":
        return "ready"
    if state:
        return state
    return "unknown"


def _device_compact_label(device: dict[str, str | None]) -> str:
    return f"{_device_name(device)} ({str(device.get('serial') or 'unknown').strip()})"


def _device_current_line(device: dict[str, str | None]) -> str:
    return " · ".join(
        [
            _device_name(device),
            str(device.get("serial") or "unknown").strip(),
            f"Android {_device_android_version(device)}",
            _device_kind(device),
        ]
    )


def _device_rows(
    devices: list[dict[str, str | None]],
    *,
    active_serial: str | None,
) -> list[list[str]]:
    rows: list[list[str]] = []
    for index, device in enumerate(devices, start=1):
        rows.append(
            [
                str(index),
                _device_name(device),
                str(device.get("serial") or "—").strip(),
                _device_kind(device),
                _device_android_version(device),
                _device_status(device, active_serial=active_serial),
            ]
        )
    return rows


def _lookup_device_by_serial(
    devices: list[dict[str, str | None]],
    serial: str | None,
) -> dict[str, str | None] | None:
    serial_text = str(serial or "").strip()
    if not serial_text:
        return None
    for device in devices:
        if str(device.get("serial") or "").strip() == serial_text:
            return device
    return None


def _print_current_device(selected_device: dict[str, str | None] | None, *, active_serial: str | None) -> None:
    menu_utils.print_section("Current device")
    if selected_device is not None:
        print(f"  {_device_current_line(selected_device)}")
        return
    if str(active_serial or "").strip():
        print(f"  saved serial {str(active_serial).strip()} not currently detected")
        return
    print("  none selected")


def get_device_selection_details(serial: str) -> dict[str, str]:
    _devices, _warnings, summaries, _serial_map = device_service.scan_devices()
    device = _lookup_device_by_serial(summaries, serial)
    if device is None:
        return {
            "name": serial,
            "serial": serial,
            "android": "—",
            "type": "device",
            "label": serial,
        }
    return {
        "name": _device_name(device),
        "serial": str(device.get("serial") or serial).strip(),
        "android": _device_android_version(device),
        "type": _device_kind(device),
        "label": _device_compact_label(device),
    }


def select_device(
    *,
    header: str = "Dynamic Run Device",
    prefer_active: bool = True,
    allow_auto_single: bool = True,
) -> tuple[str, str] | None:
    menu_utils.print_header(header)
    print("Use this device for inventory, harvest, dynamic capture, logcat, and shell actions.")
    print()
    devices, warnings, summaries, _serial_map = device_service.scan_devices()
    for warning in warnings:
        print(status_messages.status(warning, level="warn"))
    if not devices:
        print(status_messages.status("No devices detected via adb.", level="error"))
        prompt_utils.press_enter_to_continue()
        return None

    active_serial = str(device_service.get_active_serial() or "").strip() if prefer_active else ""
    active_device = _lookup_device_by_serial(summaries, active_serial)
    if active_serial:
        if active_device is not None:
            device_label = _device_compact_label(active_device)
            print(status_messages.status(f"Using current device: {device_label}", level="info"))
            return active_serial, device_label

    if allow_auto_single and len(summaries) == 1:
        selected_device = summaries[0]
        device_serial = selected_device.get("serial")
        if not device_serial:
            print(status_messages.status("Detected device missing serial.", level="error"))
            prompt_utils.press_enter_to_continue()
            return None
        device_label = _device_compact_label(selected_device)
        device_service.set_active_serial(device_serial)
        print(status_messages.status(f"Using detected device: {device_label}", level="info"))
        return device_serial, device_label

    _print_current_device(active_device, active_serial=active_serial)
    print()
    menu_utils.print_section("Detected devices")
    menu_utils.print_table(
        ["#", "Device", "Serial", "Type", "Android", "Status"],
        _device_rows(summaries, active_serial=active_serial),
    )
    print()
    print("0  Cancel")
    device_choice = prompt_utils.get_choice(
        [str(index + 1) for index in range(len(summaries))] + ["0"],
        default="1",
        prompt="› Choose device # [1]: ",
        invalid_message="Choose a listed device number or 0 to cancel.",
    )
    if device_choice == "0":
        return None
    device_index = int(device_choice) - 1
    selected_device = summaries[device_index]
    device_serial = selected_device.get("serial")
    if not device_serial:
        print(status_messages.status("Selected device missing serial.", level="error"))
        prompt_utils.press_enter_to_continue()
        return None

    device_label = _device_compact_label(selected_device)
    device_service.set_active_serial(device_serial)
    return device_serial, device_label


__all__ = ["get_device_selection_details", "select_device"]
