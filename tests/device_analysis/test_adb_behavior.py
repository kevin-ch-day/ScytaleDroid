from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from scytaledroid.DeviceAnalysis.adb import devices as adb_devices
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DeviceAnalysis.adb.errors import (
    AdbBinaryNotFoundError,
    AdbCommandError,
    AdbDeviceNotFoundError,
    AdbDeviceSelectionError,
    AdbTimeoutError,
)


ALLOWLIST = {
    "scytaledroid/DeviceAnalysis/adb/client.py",
}

ADB_SUBPROCESS_RE = re.compile(r"subprocess\.(run|Popen|call)\([^)]*['\"]adb['\"]", re.S)


def test_no_adb_subprocess_outside_adb_client():
    root = Path(__file__).resolve().parents[2]
    scytaledroid_dir = root / "scytaledroid"
    offenders = []
    for path in scytaledroid_dir.rglob("*.py"):
        rel = path.relative_to(root).as_posix()
        if rel in ALLOWLIST:
            continue
        content = path.read_text(encoding="utf-8")
        if "subprocess" not in content:
            continue
        if ADB_SUBPROCESS_RE.search(content):
            offenders.append(rel)
    assert not offenders, f"adb subprocess usage outside adb_client: {offenders}"


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


def test_run_shell_command_maps_binary_missing(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise RuntimeError("adb binary not found on PATH")

    monkeypatch.setattr(adb_shell.adb_client, "run_shell_command", fake_run)
    with pytest.raises(AdbBinaryNotFoundError):
        adb_shell.run_shell_command("serial", ["echo", "hi"])


def test_run_shell_command_maps_timeout(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise RuntimeError("adb shell foo timed out after 1s")

    monkeypatch.setattr(adb_shell.adb_client, "run_shell_command", fake_run)
    with pytest.raises(AdbTimeoutError):
        adb_shell.run_shell_command("serial", ["foo"])


def test_run_shell_check_raises_on_nonzero(monkeypatch):
    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(["adb"], 1, "", "boom")

    monkeypatch.setattr(adb_shell, "run_shell_command", fake_run)
    with pytest.raises(AdbCommandError):
        adb_shell.run_shell("serial", ["foo"], check=True)
