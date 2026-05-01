"""ADB error taxonomy used across DeviceAnalysis."""

from __future__ import annotations


class AdbError(RuntimeError):
    """Base class for ADB-related failures."""


class AdbBinaryNotFoundError(AdbError):
    """Raised when adb is not available on PATH."""


class AdbTimeoutError(AdbError):
    """Raised when an adb command exceeds the timeout."""


class AdbCommandError(AdbError):
    """Raised when adb returns a non-zero exit code."""


class AdbDeviceSelectionError(AdbError):
    """Raised when device selection is ambiguous or invalid."""


class AdbDeviceNotFoundError(AdbError):
    """Raised when a requested device serial cannot be found."""