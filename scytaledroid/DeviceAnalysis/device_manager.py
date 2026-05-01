"""device_manager.py - Track the active Android device for DeviceAnalysis."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config

from .adb import devices as adb_devices

_STATE_DIR = Path(app_config.DATA_DIR) / app_config.DEVICE_STATE_DIR
_STATE_DIR.mkdir(parents=True, exist_ok=True)
_STATE_FILE = _STATE_DIR / app_config.DEVICE_STATE_FILE

_ACTIVE_SERIAL: str | None = None
_LAST_SERIAL: str | None = None


def _load_state() -> None:
    global _ACTIVE_SERIAL
    global _LAST_SERIAL
    if not _STATE_FILE.exists():
        return
    try:
        data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        active_serial = data.get("active_serial")
        last_serial = data.get("last_serial")

        if isinstance(active_serial, str) and active_serial:
            _ACTIVE_SERIAL = active_serial
        else:
            _ACTIVE_SERIAL = None

        if isinstance(last_serial, str) and last_serial:
            _LAST_SERIAL = last_serial
        elif _ACTIVE_SERIAL:
            _LAST_SERIAL = _ACTIVE_SERIAL
        else:
            _LAST_SERIAL = None
    except Exception:
        _ACTIVE_SERIAL = None
        _LAST_SERIAL = None


def _save_state() -> None:
    payload = {}
    if _LAST_SERIAL:
        payload["last_serial"] = _LAST_SERIAL
    if _ACTIVE_SERIAL:
        payload["active_serial"] = _ACTIVE_SERIAL

    if payload:
        _STATE_FILE.write_text(json.dumps(payload), encoding="utf-8")
    elif _STATE_FILE.exists():
        try:
            _STATE_FILE.unlink()
        except OSError:
            pass


_load_state()


def get_connection_status() -> str:
    """Return a human friendly connection status."""
    return "CONNECTED" if _ACTIVE_SERIAL else "DISCONNECTED"


def get_active_serial() -> str | None:
    """Return the serial for the active device, if any."""
    return _ACTIVE_SERIAL


def get_active_device() -> dict[str, str | None | None]:
    """Return metadata for the active device or ``None`` when disconnected."""
    serial = _ACTIVE_SERIAL
    if not serial:
        return None

    devices = adb_devices.list_devices()
    for device in devices:
        if device.get("serial") == serial:
            return device

    # Active device disappeared from adb listing; reset state.
    disconnect()
    return None


def set_active_device(serial: str) -> bool:
    """Promote a device to active if it exists in the adb inventory."""
    global _ACTIVE_SERIAL
    global _LAST_SERIAL
    devices = adb_devices.list_devices()
    for device in devices:
        if device.get("serial") == serial:
            _ACTIVE_SERIAL = serial
            _LAST_SERIAL = serial
            _save_state()
            return True

    print(f"[DeviceManager] Device with serial '{serial}' not found.")
    return False


def disconnect() -> None:
    """Forget the current active device."""
    global _ACTIVE_SERIAL
    global _LAST_SERIAL
    if _ACTIVE_SERIAL:
        _LAST_SERIAL = _ACTIVE_SERIAL
    _ACTIVE_SERIAL = None
    _save_state()


def describe_active_device() -> str:
    """Return a label describing the active device or 'None'."""
    active = get_active_device()
    if not active:
        return "None"
    return adb_devices.get_device_label(active)


def get_last_serial() -> str | None:
    """Return the most recently active device serial, if tracked."""
    return _LAST_SERIAL
