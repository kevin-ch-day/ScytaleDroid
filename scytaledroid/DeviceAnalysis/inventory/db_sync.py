"""App definition synchronization helpers (UI-free)."""

from __future__ import annotations

from typing import Sequence

from scytaledroid.DeviceAnalysis.inventory.package_collection import PackageRow
from scytaledroid.Database.db_func.harvest.apk_repository import ensure_app_definition


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
        try:
            ensure_app_definition(pkg, app_label)
            synced += 1
        except Exception:
            # Fail silently; the interactive path will log this at higher layers.
            continue
    return synced
