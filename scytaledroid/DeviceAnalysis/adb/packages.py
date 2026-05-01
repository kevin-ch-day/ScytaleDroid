"""Package inventory helpers for adb-backed workflows."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis import package_info, package_inventory


def list_packages(serial: str) -> list[str]:
    """Return package names via pm list packages."""
    return package_inventory.list_packages(serial)


def list_packages_with_versions(
    serial: str,
    *,
    allow_fallbacks: bool = False,
) -> list[tuple[str, str | None, str | None]]:
    """Return package identifiers with version metadata."""
    return package_inventory.list_packages_with_versions(serial, allow_fallbacks=allow_fallbacks)


def get_package_paths(
    serial: str,
    package_name: str,
    refresh: bool = False,
    *,
    allow_fallbacks: bool = False,
) -> list[str]:
    """Return canonical APK paths for a package using pm path."""
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
) -> dict[str, str | None]:
    """Return metadata for a package via pm dump (cached)."""
    return package_info.get_package_metadata(serial, package_name, refresh=refresh)


__all__ = [
    "list_packages",
    "list_packages_with_versions",
    "get_package_paths",
    "get_package_metadata",
]