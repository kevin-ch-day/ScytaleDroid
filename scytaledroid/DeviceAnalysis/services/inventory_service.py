"""Inventory service façade for menus/controllers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import os

from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DeviceAnalysis.inventory import runner, snapshot_io, progress, views
from scytaledroid.Utils.DisplayUtils import status_messages


@dataclass
class InventorySnapshotInfo:
    status_label: str
    age_seconds: float
    total_packages: int
    last_sync_utc: Optional[datetime]


class InventoryServiceError(Exception):
    """Raised when an inventory operation fails at the service boundary."""


def get_latest_snapshot_info(serial: str) -> Optional[InventorySnapshotInfo]:
    meta = snapshot_io.load_latest_snapshot_meta(serial)
    if meta is None:
        return None
    return InventorySnapshotInfo(
        status_label=getattr(meta, "status_label", "UNKNOWN"),
        age_seconds=getattr(meta, "age_seconds", 0.0),
        total_packages=getattr(meta, "package_count", 0),
        last_sync_utc=getattr(meta, "captured_at", None),
    )


def run_full_sync(
    serial: str,
    ui_prefs,
    *,
    progress_sink: str = "cli",
    mode: Optional[str] = None,
) -> runner.InventoryResult:
    """
    High-level entry point for a full inventory sync.
    """
    if not serial:
        raise InventoryServiceError("No device serial provided for inventory sync.")

    active = device_manager.get_active_device()
    if not active or active.get("serial") != serial:
        # Attempt to set active if possible
        device_manager.set_active_device(serial)

    meta = snapshot_io.load_latest_snapshot_meta(serial)
    mode = (mode or os.getenv("SCYTALEDROID_INVENTORY_MODE", "baseline")).lower().strip()
    progress_cb = None
    if progress_sink == "cli":
        progress.render_snapshot_block(meta, ui_prefs=ui_prefs, mode=mode)
        progress_cb = progress.make_cli_progress_printer(ui_prefs=ui_prefs)

    try:
        result = runner.run_full_sync(
            serial=serial, filter_fn=None, progress_cb=progress_cb, mode=mode
        )
    except Exception as exc:  # pragma: no cover - map to service error
        raise InventoryServiceError(f"Inventory sync failed for {serial}: {exc}") from exc

    if progress_sink == "cli":
        if mode == "legacy":
            print(
                status_messages.status(
                    "SCYTALEDROID_INVENTORY_MODE=legacy is deprecated; use baseline/user_only/bulk modes.",
                    level="warn",
                )
            )
        views.print_inventory_run_summary_from_result(result)
        print(
            status_messages.status(
                'Next steps: choose "Pull APKs" from Device Analysis to harvest artifacts for static analysis.',
                level="info",
            )
        )

    return result
