"""Reload local inventory rows after a sync — shared harvest-plan / workflow helper."""

from __future__ import annotations

from typing import Literal

from scytaledroid.DeviceAnalysis import harvest, inventory

ReloadHarvestFailure = Literal["missing", "empty_rows"]


def reload_harvest_inventory_after_sync(serial: str) -> tuple[list[harvest.InventoryRow], int | None, str | None] | ReloadHarvestFailure:
    """Reload the latest persisted snapshot after inventory_service / workflow sync.

    Returns ``\"missing\"`` when there is no snapshot or empty ``packages``.
    Returns ``\"empty_rows\"`` when rows cannot be built (caller picks scoped vs full UI).
    On success returns ``(rows, snapshot_id|None, captured_at|None)``.
    """
    snapshot = inventory.load_latest_inventory(serial)
    if not snapshot or not snapshot.get("packages"):
        return "missing"

    packages = snapshot.get("packages", [])
    rows = harvest.build_inventory_rows(packages)
    if not rows:
        return "empty_rows"

    snapshot_id_raw = snapshot.get("snapshot_id")
    snapshot_id = snapshot_id_raw if isinstance(snapshot_id_raw, int) else None
    captured = snapshot.get("generated_at")
    captured_at = str(captured) if captured else None
    return rows, snapshot_id, captured_at


__all__ = ["reload_harvest_inventory_after_sync", "ReloadHarvestFailure"]
