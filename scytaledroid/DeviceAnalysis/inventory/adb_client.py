"""Thin wrappers around adb calls used during inventory collection."""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from scytaledroid.DeviceAnalysis import adb_cache, adb_devices, adb_packages
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from . import adb_bulk
from scytaledroid.DeviceAnalysis.modes.inventory import InventoryMode


def list_packages(
    serial: str,
    use_bulk: Optional[bool],
    *,
    allow_fallbacks: bool = False,
) -> Tuple[List[Tuple[str, Optional[str], Optional[str]]], List[str], bool, bool]:
    """Return (packages_with_versions, package_names, bulk_used, fallback_used)."""
    packages_with_versions: List[Tuple[str, Optional[str], Optional[str]]] = []
    bulk_used = False
    fallback_used = False

    if use_bulk is None:
        env_mode = os.getenv("SCYTALEDROID_INVENTORY_MODE", InventoryMode.BASELINE.value).strip().lower()
        try:
            resolved_mode = InventoryMode(env_mode)
        except ValueError:
            resolved_mode = InventoryMode.BASELINE
        use_bulk = resolved_mode == InventoryMode.BULK

    if use_bulk:
        bulk_entries = adb_bulk.list_packages_bulk(serial)
        if bulk_entries:
            packages_with_versions = [(entry.package_name, None, None) for entry in bulk_entries]
            bulk_used = True
        else:
            if not allow_fallbacks:
                log.warning(
                    "Inventory fallback blocked: bulk listing returned no entries.",
                    category="inventory",
                    extra={
                        "event": "inventory.fallback_blocked",
                        "reason": "bulk_list_empty",
                        "serial": serial,
                    },
                )
                raise RuntimeError(
                    "Inventory fallback blocked (bulk listing empty). "
                    "Enable inventory fallbacks in the Device Analysis menu to proceed."
                )
            log.warning(
                "Inventory fallback invoked: bulk listing returned no entries; "
                "using per-package listing.",
                category="inventory",
                extra={
                    "event": "inventory.fallback",
                    "reason": "bulk_list_empty",
                    "serial": serial,
                },
            )
            fallback_used = True

    if not packages_with_versions:
        packages_with_versions = adb_packages.list_packages_with_versions(
            serial, allow_fallbacks=allow_fallbacks
        )
        if use_bulk:
            fallback_used = True

    package_names = [entry[0] for entry in packages_with_versions if entry and entry[0]]
    return packages_with_versions, package_names, bulk_used, fallback_used


def clear_package_caches(serial: str) -> None:
    adb_cache.PACKAGE_PATH_CACHE.clear(serial=serial)
    adb_cache.PACKAGE_META_CACHE.clear(serial=serial)


def get_package_paths(
    serial: str,
    package_name: str,
    *,
    allow_fallbacks: bool = False,
) -> List[str]:
    return adb_packages.get_package_paths(
        serial,
        package_name,
        allow_fallbacks=allow_fallbacks,
    )


def get_package_metadata(serial: str, package_name: str) -> Dict[str, Optional[str]]:
    return adb_packages.get_package_metadata(serial, package_name)


def get_device_properties(serial: str) -> Dict[str, str]:
    return adb_devices.get_basic_properties(serial)
