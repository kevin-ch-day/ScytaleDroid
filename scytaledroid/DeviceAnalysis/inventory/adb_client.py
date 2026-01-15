"""Thin wrappers around adb calls used during inventory collection."""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from scytaledroid.DeviceAnalysis import adb_utils
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from . import adb_bulk
from .modes import InventoryMode


def list_packages(serial: str, use_bulk: Optional[bool]) -> Tuple[List[Tuple[str, Optional[str], Optional[str]]], List[str], bool]:
    """Return (packages_with_versions, package_names, bulk_used)."""
    packages_with_versions: List[Tuple[str, Optional[str], Optional[str]]] = []
    bulk_used = False

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
            log.warning(
                "Bulk package listing returned no entries; falling back to legacy per-package listing.",
                category="inventory",
            )

    if not packages_with_versions:
        packages_with_versions = adb_utils.list_packages_with_versions(serial)

    package_names = [entry[0] for entry in packages_with_versions if entry and entry[0]]
    return packages_with_versions, package_names, bulk_used


def clear_package_caches(serial: str) -> None:
    adb_utils.clear_package_caches(serial)


def get_package_paths(serial: str, package_name: str) -> List[str]:
    return adb_utils.get_package_paths(serial, package_name)


def get_package_metadata(serial: str, package_name: str) -> Dict[str, Optional[str]]:
    return adb_utils.get_package_metadata(serial, package_name)


def get_device_properties(serial: str) -> Dict[str, str]:
    return adb_utils.get_basic_properties(serial)
