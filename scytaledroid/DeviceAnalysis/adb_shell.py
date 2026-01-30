"""ADB shell execution helpers with defaults + error mapping."""

from __future__ import annotations

import subprocess
from typing import Optional, Sequence

from scytaledroid.DeviceAnalysis import adb_client
from scytaledroid.DeviceAnalysis.adb_errors import (
    AdbBinaryNotFoundError,
    AdbCommandError,
    AdbError,
    AdbTimeoutError,
)

# Default timeouts (seconds)
ADB_TIMEOUT_DEFAULT = 30.0
ADB_TIMEOUT_LONG = 120.0
ADB_TIMEOUT_DISCOVERY = 10.0


def run_shell_command(
    serial: str,
    command: Sequence[str],
    *,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess[str]:
    """Execute an adb shell command and return CompletedProcess."""
    try:
        return adb_client.run_shell_command(serial, command, timeout=timeout or ADB_TIMEOUT_DEFAULT)
    except RuntimeError as exc:
        _raise_mapped_error(exc)
    raise AdbError("Unexpected adb shell failure")


def run_shell(
    serial: str,
    command: Sequence[str],
    *,
    timeout: Optional[float] = None,
    check: bool = False,
) -> str:
    """Execute an adb shell command and return stdout."""
    completed = run_shell_command(serial, command, timeout=timeout)
    if check and completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise AdbCommandError(
            f"adb shell {' '.join(command)} exited with {completed.returncode}: {stderr}"
        )
    return completed.stdout or ""


def _raise_mapped_error(exc: RuntimeError) -> None:
    message = str(exc).lower()
    if "adb binary not found" in message:
        raise AdbBinaryNotFoundError(str(exc)) from exc
    if "timed out" in message:
        raise AdbTimeoutError(str(exc)) from exc
    raise AdbError(str(exc)) from exc


__all__ = [
    "ADB_TIMEOUT_DEFAULT",
    "ADB_TIMEOUT_LONG",
    "ADB_TIMEOUT_DISCOVERY",
    "run_shell_command",
    "run_shell",
]
