"""App definition synchronization helpers (UI-free)."""

from __future__ import annotations

from collections.abc import Sequence

from scytaledroid.Database.db_func.harvest.apk_repository import ensure_app_definition
from scytaledroid.Database.db_utils.package_utils import is_invalid_package_name
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.DeviceAnalysis.inventory.package_collection import PackageRow


def sync_app_definitions(rows: Sequence[PackageRow]) -> int:
    """
    Ensure app definitions exist for the given inventory rows.

    Returns:
        int: number of definitions created/updated.

    """
    synced = 0
    for row in rows:
        pkg = row.get("package_name") if isinstance(row, dict) else None
        app_label = row.get("app_label") if isinstance(row, dict) else None
        if not pkg:
            continue
        if is_invalid_package_name(str(pkg)):
            log.warning(
                f"Skipping invalid package token during app-definition sync: {pkg!r}",
                category="inventory",
            )
            continue
        try:
            ensure_app_definition(pkg, app_label)
            synced += 1
        except Exception:
            # Fail silently; the interactive path will log this at higher layers.
            continue
    return synced
