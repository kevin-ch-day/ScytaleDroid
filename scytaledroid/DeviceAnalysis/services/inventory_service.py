"""Inventory service façade for menus/controllers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import os

from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DeviceAnalysis.inventory import runner, snapshot_io, progress, views
from scytaledroid.DeviceAnalysis.inventory.errors import InventoryCollectionError
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger
from scytaledroid.Utils.LoggingUtils import logging_events as log_events


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
        progress.render_snapshot_block(meta, ui_prefs=ui_prefs, mode=mode, serial=serial)
        progress_cb = progress.make_cli_progress_printer(ui_prefs=ui_prefs)

    # Structured RUN_START log
    run_ctx = RunContext(
        subsystem="inventory",
        device_serial=serial,
        device_model=(
            getattr(meta, "device_model", None)
            if meta
            else (active.get("model") if active else None)
        ),
        run_id=f"INV-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        scope=mode,
        profile=mode,
    )
    try:
        inventory_logger = get_run_logger("device", run_ctx)
        inventory_logger.info(
            "Inventory RUN_START",
            extra={
                "event": log_events.RUN_START,
                "previous_snapshot": getattr(meta, "snapshot_path", None) if meta else None,
                "staleness_threshold": getattr(meta, "staleness_seconds", None)
                if meta
                else getattr(progress, "INVENTORY_STALE_SECONDS", None),
            },
        )
    except Exception:
        inventory_logger = None

    try:
        result = runner.run_full_sync(
            serial=serial, filter_fn=None, progress_cb=progress_cb, mode=mode
        )
    except InventoryCollectionError as exc:  # pragma: no cover - map to service error
        completed = max(0, exc.index - 1)
        msg = (
            f"Inventory sync failed for {serial}: package={exc.package} "
            f"stage={exc.stage} progress={completed}/{exc.total}. "
            "Run aborted before persistence; last good snapshot preserved."
        )
        print(status_messages.status(msg, level="error"))
        raise InventoryServiceError(msg) from exc
    except Exception as exc:  # pragma: no cover - map to service error
        msg = (
            f"Inventory sync failed for {serial}: {exc}. "
            "Run aborted before persistence; last good snapshot preserved."
        )
        print(status_messages.status(msg, level="error"))
        raise InventoryServiceError(msg) from exc

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

    # Emit structured run summary to logs for reproducibility.
    try:
        delta = getattr(result, "delta", None)
        # Policy/filter insight: user vs non-user counts
        user_count = 0
        non_user_count = 0
        source_counts = {}
        for row in getattr(result, "rows", []):
            primary_path = str(row.get("primary_path") or "")
            if primary_path.startswith("/data/"):
                user_count += 1
                src = str(row.get("source") or "Unknown")
                source_counts[src] = source_counts.get(src, 0) + 1
            else:
                non_user_count += 1
        if inventory_logger:
            inventory_logger.info(
                "Inventory policy.filter",
                extra={
                    "event": log_events.POLICY_FILTER,
                    "user_scope_candidates": user_count,
                    "non_user_scope": non_user_count,
                    "install_sources_user": source_counts,
                },
            )
        summary_payload = {
            "event": log_events.RUN_END,
            "snapshot_path": str(getattr(result, "snapshot_path", "")),
            "packages": getattr(result.stats, "total_packages", None),
            "split_packages": getattr(result.stats, "split_packages", None),
            "delta_new": getattr(delta, "new_count", None) if delta else None,
            "delta_removed": getattr(delta, "removed_count", None) if delta else None,
            "delta_updated": getattr(delta, "updated_count", None) if delta else None,
            "elapsed_seconds": getattr(result, "elapsed_seconds", None),
        }
        (inventory_logger or get_run_logger("device", run_ctx)).info(
            "Inventory RUN_END", extra=summary_payload
        )
        if inventory_logger:
            inventory_logger.info(
                "Inventory db.persist",
                extra={
                    "event": log_events.DB_PERSIST,
                    "entity": "inventory.app_definitions",
                    "rows": len(getattr(result, "rows", [])),
                    "synced": getattr(result, "synced_app_definitions", None),
                },
            )
    except Exception:
        pass

    return result
