"""adb_utils.py - Compatibility facade for ADB helpers."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from scytaledroid.DeviceAnalysis import adb_cache, adb_client, device_info, device_status
from scytaledroid.DeviceAnalysis import package_info, package_inventory


def is_available() -> bool:
    """Return True when the adb binary is available on PATH."""
    return adb_client.is_available()


def get_adb_binary() -> Optional[str]:
    """Expose the adb binary path for other helpers."""
    return adb_client.get_adb_binary()


def scan_devices() -> Tuple[List[Dict[str, Optional[str]]], List[str]]:
    """Return devices and any informational warnings gathered during discovery."""
    return device_info.scan_devices()


def list_devices() -> List[Dict[str, Optional[str]]]:
    """Return the list of devices reported by ``adb devices -l``."""
    return device_info.list_devices()


def get_device_label(device: Dict[str, Optional[str]]) -> str:
    """Return a short human-readable label for a device entry."""
    return device_info.get_device_label(device)


def run_shell_command(
    serial: str,
    command: List[str],
    *,
    timeout: Optional[float] = None,
):
    """Execute an arbitrary ``adb shell`` command for the selected device."""
    return adb_client.run_shell_command(serial, command, timeout=timeout)


def run_shell(
    serial: str,
    command: List[str],
    *,
    timeout: Optional[float] = None,
    check: bool = False,
) -> str:
    """Execute an adb shell command and return stdout text."""
    return adb_client.run_shell(serial, command, timeout=timeout, check=check)


def get_basic_properties(serial: str) -> Dict[str, str]:
    """Return curated device properties plus derived metadata."""
    return device_info.get_basic_properties(serial)


def build_device_summary(device: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
    """Attach basic properties and derived metadata to a device listing."""
    return device_info.build_device_summary(device)


def list_packages(serial: str) -> List[str]:
    """Return package names via ``pm list packages``."""
    return package_inventory.list_packages(serial)


def list_packages_with_versions(
    serial: str,
    *,
    allow_fallbacks: bool = False,
) -> List[Tuple[str, Optional[str], Optional[str]]]:
    """Return package identifiers along with version metadata when available."""
    return package_inventory.list_packages_with_versions(serial, allow_fallbacks=allow_fallbacks)


def get_package_paths(
    serial: str,
    package_name: str,
    refresh: bool = False,
    *,
    allow_fallbacks: bool = False,
) -> List[str]:
    """Return canonical APK paths for a package using ``pm path``."""
    return package_info.get_package_paths(
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
    return package_info.get_package_metadata(serial, package_name, refresh=refresh)


def get_device_stats(serial: str) -> Dict[str, Optional[str]]:
    """Collect live telemetry for the provided device."""
    return device_status.get_device_stats(serial)


def get_device_capabilities(serial: str) -> Dict[str, Optional[str]]:
    """Return capability snapshot for dynamic analysis."""
    return device_status.get_device_capabilities(serial)


def clear_package_caches(serial: Optional[str] = None) -> None:
    """Clear cached package metadata and paths."""
    adb_cache.PACKAGE_PATH_CACHE.clear(serial=serial)
    adb_cache.PACKAGE_META_CACHE.clear(serial=serial)
