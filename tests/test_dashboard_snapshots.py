from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout

from scytaledroid.DeviceAnalysis.device_menu import dashboard
from scytaledroid.Utils.DisplayUtils import colors
from scytaledroid.Utils.DisplayUtils import terminal as term


def _stub_summary() -> dict[str, str]:
    return {
        "serial": "ZY22JK89DR",
        "state": "device",
        "model": "moto_g_5G",
        "device": "motog",
        "android_release": "Android 15",
        "battery_level": "100%",
        "battery_status": "Charging",
        "wifi_state": "On",
        "is_rooted": "No",
        "manufacturer": "Motorola",
        "device_type": "Physical",
    }


def _capture_dashboard(summaries, active):
    f = io.StringIO()
    serial_map = {s["serial"]: s for s in summaries if s.get("serial")}
    # Ensure ASCII/Unicode mode is determined using the real stdout
    term.use_ascii_ui(force_refresh=True)
    with redirect_stdout(f):
        dashboard.print_dashboard(
            summaries,
            active,
            warnings=[],
            last_refresh_ts=0,
            serial_map=serial_map,
        )
    return colors.strip(f.getvalue()).splitlines()


def test_snapshot_disconnected_widths(monkeypatch):
    # Width 60
    monkeypatch.setenv("COLUMNS", "60")
    term.get_terminal_width(force_refresh=True)
    lines_60 = _capture_dashboard([_stub_summary()], None)
    assert any("Device Dashboard" in line for line in lines_60)
    assert any("No active device" in line for line in lines_60)
    assert len(lines_60) <= 24

    # Width 80
    monkeypatch.setenv("COLUMNS", "80")
    term.get_terminal_width(force_refresh=True)
    lines_80 = _capture_dashboard([_stub_summary()], None)
    assert any("Device Dashboard" in line for line in lines_80)
    assert any("No active device" in line for line in lines_80)
    assert len(lines_80) <= 24


def test_snapshot_connected_widths(monkeypatch):
    active = _stub_summary()

    # Width 60
    monkeypatch.setenv("COLUMNS", "60")
    term.get_terminal_width(force_refresh=True)
    lines_60 = _capture_dashboard([active], active)
    assert any("ADB: CONNECTED" in line or "ADB: UNKNOWN" in line for line in lines_60)
    assert len(lines_60) <= 24

    # Width 80
    monkeypatch.setenv("COLUMNS", "80")
    term.get_terminal_width(force_refresh=True)
    lines_80 = _capture_dashboard([active], active)
    assert any("ADB: CONNECTED" in line or "ADB: UNKNOWN" in line for line in lines_80)
    assert len(lines_80) <= 24
