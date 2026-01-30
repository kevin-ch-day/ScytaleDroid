"""adb_utils.py - Compatibility facade for ADB helpers (deprecated)."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple
import logging

from scytaledroid.DeviceAnalysis import adb_cache, adb_client
from scytaledroid.DeviceAnalysis import adb_devices, adb_packages, adb_status, adb_shell

_LOGGER = logging.getLogger(__name__)
_DEPRECATION_WARNED = False


def _warn_deprecated() -> None:
    global _DEPRECATION_WARNED
    if _DEPRECATION_WARNED:
        return
    _DEPRECATION_WARNED = True
    _LOGGER.warning(
        "adb_utils is deprecated; use adb_shell/adb_devices/adb_packages/adb_status directly. "
        "Removal milestone: MILESTONE-DYNAMIC-C."
    )


_warn_deprecated()


def is_available() -> bool:
    """Return True when the adb binary is available on PATH."""
    return adb_client.is_available()


def get_adb_binary() -> Optional[str]:
    """Expose the adb binary path for other helpers."""
    return adb_client.get_adb_binary()


def scan_devices() -> Tuple[List[Dict[str, Optional[str]]], List[str]]:
    """Return devices and any informational warnings gathered during discovery."""
    return adb_devices.scan_devices()


def list_devices() -> List[Dict[str, Optional[str]]]:
    """Return the list of devices reported by ``adb devices -l``."""
    return adb_devices.list_devices()


def get_device_label(device: Dict[str, Optional[str]]) -> str:
    """Return a short human-readable label for a device entry."""
    return adb_devices.get_device_label(device)


def run_shell_command(
    serial: str,
    command: List[str],
    *,
    timeout: Optional[float] = None,
):
    """Execute an arbitrary ``adb shell`` command for the selected device."""
    return adb_shell.run_shell_command(serial, command, timeout=timeout)


def run_shell(
    serial: str,
    command: List[str],
    *,
    timeout: Optional[float] = None,
    check: bool = False,
) -> str:
    """Execute an adb shell command and return stdout text."""
    return adb_shell.run_shell(serial, command, timeout=timeout, check=check)


def get_basic_properties(serial: str) -> Dict[str, str]:
    """Return curated device properties plus derived metadata."""
    return adb_devices.get_basic_properties(serial)


def build_device_summary(device: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
    """Attach basic properties and derived metadata to a device listing."""
    return adb_devices.build_device_summary(device)


def list_packages(serial: str) -> List[str]:
    """Return package names via ``pm list packages``."""
    return adb_packages.list_packages(serial)


def list_packages_with_versions(
    serial: str,
    *,
    allow_fallbacks: bool = False,
) -> List[Tuple[str, Optional[str], Optional[str]]]:
    """Return package identifiers along with version metadata when available."""
    return adb_packages.list_packages_with_versions(serial, allow_fallbacks=allow_fallbacks)


def get_package_paths(
    serial: str,
    package_name: str,
    refresh: bool = False,
    *,
    allow_fallbacks: bool = False,
) -> List[str]:
    """Return canonical APK paths for a package using ``pm path``."""
    return adb_packages.get_package_paths(
        serial,
        package_name,
        refresh=refresh,
        allow_fallbacks=allow_fallbacks,
    )


def get_package_metadata(
    serial: str,
    package_name: str,
    refresh: bool = False,
) -> Dict[str, Optional[str]]:
    """Return metadata for a package via ``pm dump`` (cached)."""
    return adb_packages.get_package_metadata(serial, package_name, refresh=refresh)


def get_device_stats(serial: str) -> Dict[str, Optional[str]]:
    """Collect live telemetry for the provided device."""
    return adb_status.get_device_stats(serial)


def get_device_capabilities(serial: str) -> Dict[str, Optional[str]]:
    """Return capability snapshot for dynamic analysis."""
    return adb_status.get_device_capabilities(serial)


def clear_package_caches(serial: Optional[str] = None) -> None:
    """Clear cached package metadata and paths."""
    adb_cache.PACKAGE_PATH_CACHE.clear(serial=serial)
    adb_cache.PACKAGE_META_CACHE.clear(serial=serial)
