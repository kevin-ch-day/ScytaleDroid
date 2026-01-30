import pytest

from scytaledroid.DeviceAnalysis import adb_devices
from scytaledroid.DeviceAnalysis.adb_errors import (
    AdbDeviceNotFoundError,
    AdbDeviceSelectionError,
)


def test_resolve_serial_single_device():
    devices = [{"serial": "abc123", "state": "device"}]
    assert adb_devices.resolve_serial(devices, None) == "abc123"


def test_resolve_serial_multiple_devices_requires_explicit():
    devices = [{"serial": "abc123"}, {"serial": "def456"}]
    with pytest.raises(AdbDeviceSelectionError):
        adb_devices.resolve_serial(devices, None)


def test_resolve_serial_unknown_requested():
    devices = [{"serial": "abc123"}]
    with pytest.raises(AdbDeviceNotFoundError):
        adb_devices.resolve_serial(devices, "zzz999")
