import subprocess

import pytest
from scytaledroid.DeviceAnalysis import adb_shell
from scytaledroid.DeviceAnalysis.adb_errors import (
    AdbBinaryNotFoundError,
    AdbCommandError,
    AdbTimeoutError,
)


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
