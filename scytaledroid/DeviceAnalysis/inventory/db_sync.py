"""App definition synchronization helpers (UI-free)."""

from __future__ import annotations

from collections.abc import Sequence

from scytaledroid.Database.db_func.harvest.apk_repository import (
    bulk_ensure_app_definitions,
    ensure_app_definition,
)
from scytaledroid.Database.db_utils.package_utils import is_invalid_package_name
from scytaledroid.DeviceAnalysis.inventory.package_collection import PackageRow
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def sync_app_definitions(rows: Sequence[PackageRow]) -> int:
    """
    Ensure app definitions exist for the given inventory rows.

    Returns:
        int: number of definitions created/updated.

    """
    prepared: list[tuple[str, str | None]] = []
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
        prepared.append((str(pkg), str(app_label) if app_label is not None else None))

    if not prepared:
        return 0
    try:
        return bulk_ensure_app_definitions(prepared)
    except Exception:
        synced = 0
        for pkg, label in prepared:
            try:
                ensure_app_definition(pkg, label)
                synced += 1
            except Exception:
                continue
        return synced
