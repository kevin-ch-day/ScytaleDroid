"""ADB client utilities for shell execution and binary resolution."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence

from scytaledroid.DeviceAnalysis.adb_errors import AdbBinaryNotFoundError


def _resolve_adb() -> str | None:
    """Return the adb binary path when available."""
    return shutil.which("adb")


def is_available() -> bool:
    """Return True when the adb binary is available on PATH."""
    return _resolve_adb() is not None


def get_adb_binary() -> str | None:
    """Expose the adb binary path for other helpers."""
    return _resolve_adb()


def run_shell_command(
    serial: str,
    command: Sequence[str],
    *,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute an arbitrary ``adb shell`` command for the selected device."""
    adb_bin = _resolve_adb()
    if adb_bin is None:
        raise AdbBinaryNotFoundError("adb binary not found on PATH")

    adb_command = [adb_bin, "-s", serial, "shell", *command]
    try:
        return subprocess.run(
            adb_command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - defensive
        raise RuntimeError(
            f"adb shell {' '.join(command)} timed out after {timeout}s"
        ) from exc


def run_adb_command(
    args: Sequence[str],
    *,
    timeout: float | None = None,
    capture_output: bool = True,
    text: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Execute a raw adb command (non-shell)."""
    adb_bin = _resolve_adb()
    if adb_bin is None:
        raise AdbBinaryNotFoundError("adb binary not found on PATH")
    adb_command = [adb_bin, *args]
    try:
        return subprocess.run(
            adb_command,
            capture_output=capture_output,
            text=text,
            check=check,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - defensive
        raise RuntimeError(
            f"adb {' '.join(args)} timed out after {timeout}s"
        ) from exc


def run_adb_interactive_shell(serial: str) -> int:
    """Launch an interactive adb shell for the provided serial."""
    adb_bin = _resolve_adb()
    if adb_bin is None:
        raise AdbBinaryNotFoundError("adb binary not found on PATH")
    return subprocess.call([adb_bin, "-s", serial, "shell"])


def run_adb_popen(
    args: Sequence[str],
    *,
    stdout=None,
    stderr=None,
    text: bool = True,
) -> subprocess.Popen[str]:
    """Launch a long-running adb process."""
    adb_bin = _resolve_adb()
    if adb_bin is None:
        raise AdbBinaryNotFoundError("adb binary not found on PATH")
    return subprocess.Popen([adb_bin, *args], stdout=stdout, stderr=stderr, text=text)


def run_shell(
    serial: str,
    command: Sequence[str],
    *,
    timeout: float | None = None,
    check: bool = False,
) -> str:
    """
    Execute an adb shell command and return stdout text.

    Args:
        serial: device serial
        command: list of command tokens to run after ``adb shell``
        timeout: optional timeout in seconds
        check: when True, raise RuntimeError on non-zero return code
    """
    completed = run_shell_command(serial, command, timeout=timeout)
    if check and completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(
            f"adb shell {' '.join(command)} exited with {completed.returncode}: {stderr}"
        )
    return completed.stdout or ""