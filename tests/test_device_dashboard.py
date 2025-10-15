from __future__ import annotations

from scytaledroid.DeviceAnalysis.device_menu import dashboard
from scytaledroid.Utils.DisplayUtils import colors


def test_connection_badge_formats_status(force_color):
    connected = dashboard._connection_badge("connected")
    disconnected = dashboard._connection_badge("offline")

    assert colors.strip(connected) == "● CONNECTED"
    assert "\033[" in connected
    assert colors.strip(disconnected) == "● OFFLINE"


def test_device_table_rows_colours_state_and_root(force_color):
    summary = {
        "serial": "ZY22JK89DR",
        "state": "device",
        "model": "moto_g_5G",
        "device": "motog",
        "android_release": "Android 15",
        "battery_level": "85%",
        "battery_status": "Charging",
        "wifi_state": "On",
        "is_rooted": "No",
    }

    rows = dashboard._device_table_rows([summary])
    assert len(rows) == 1
    device_label, state, android, battery, wifi, root = rows[0]

    assert "moto" in device_label.lower()
    assert colors.strip(state) == "● DEVICE"
    assert android == "Android 15"
    assert "85%" in battery
    assert wifi == "On"
    assert colors.strip(root) == "● NO"


def test_no_device_line_when_disconnected():
    line_with_devices = dashboard._no_device_line(devices_found=1)
    line_without_devices = dashboard._no_device_line(devices_found=0)
    assert "No active device" in line_with_devices
    assert "No devices detected" in line_without_devices


def test_status_badge_ascii(monkeypatch):
    from scytaledroid.Utils.DisplayUtils import terminal
    baseline = terminal.use_ascii_ui(force_refresh=True)
    monkeypatch.setenv("ASCII_UI", "1")
    try:
        terminal.use_ascii_ui(force_refresh=True)
        badge = dashboard._status_badge("connected")
        assert colors.strip(badge).startswith("* CONNECTED")
    finally:
        monkeypatch.delenv("ASCII_UI", raising=False)
        terminal.use_ascii_ui(force_refresh=True)
    assert terminal.use_ascii_ui(force_refresh=True) == baseline
