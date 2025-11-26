"""App definition synchronization helpers (UI-free)."""

from __future__ import annotations

from typing import Sequence

from scytaledroid.DeviceAnalysis.inventory.package_collection import PackageRow


def sync_app_definitions(rows: Sequence[PackageRow]) -> int:
    """
    Ensure app definitions exist for the given inventory rows.

    Returns:
        int: number of definitions created/updated.

    NOTE: placeholder; migrate logic from inventory.py (ensure_app_definition).
    """
    raise NotImplementedError("sync_app_definitions must be implemented from existing logic.")

