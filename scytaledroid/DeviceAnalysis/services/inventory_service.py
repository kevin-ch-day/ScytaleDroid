"""Inventory service façade for menus/controllers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime

from scytaledroid.DeviceAnalysis import device_manager, inventory_meta
from scytaledroid.DeviceAnalysis.inventory import progress, runner, snapshot_io, views
from scytaledroid.DeviceAnalysis.inventory.errors import InventoryCollectionError
from scytaledroid.DeviceAnalysis.modes.inventory import InventoryConfig
from scytaledroid.DeviceAnalysis.runtime_flags import allow_inventory_fallbacks
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_events as log_events
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger


@dataclass
class InventorySnapshotInfo:
    status_label: str
    age_seconds: float
    total_packages: int
    last_sync_utc: datetime | None


class InventoryServiceError(Exception):
    """Raised when an inventory operation fails at the service boundary."""


def get_latest_snapshot_info(serial: str) -> InventorySnapshotInfo | None:
    meta = snapshot_io.load_latest_snapshot_meta(serial)
    if meta is None:
        return None
    return InventorySnapshotInfo(
        status_label=getattr(meta, "status_label", "UNKNOWN"),
        age_seconds=getattr(meta, "age_seconds", 0.0),
        total_packages=getattr(meta, "package_count", 0),
        last_sync_utc=getattr(meta, "captured_at", None),
    )


def load_latest_inventory(serial: str) -> dict[str, object | None]:
    """Return the latest inventory snapshot payload for a device."""
    return snapshot_io.load_latest_inventory(serial)


def load_latest_snapshot_meta(serial: str):
    """Return the latest inventory snapshot metadata."""
    return snapshot_io.load_latest_snapshot_meta(serial)


def compute_name_hash(names: list[str]) -> str | None:
    """Return a stable hash for a list of package names."""
    return inventory_meta.compute_name_hash(names)


def snapshot_signatures(packages: list[dict[str, object | None]]):
    """Return signature tuples for the provided snapshot packages."""
    return inventory_meta.snapshot_signatures(packages)


def compute_signature_hash(signatures) -> str | None:
    """Return a stable hash for package signatures."""
    return inventory_meta.compute_signature_hash(signatures)


def compute_scope_hash(entries: list[dict[str, object]]) -> str | None:
    """Return a stable hash for scope entries."""
    return inventory_meta.compute_scope_hash(entries)


def update_scope_hash(serial: str, scope_id: str, scope_hash: str | None):
    """Persist scope hash metadata for the device."""
    return inventory_meta.update_scope_hash(serial, scope_id, scope_hash)


def run_full_sync(
    serial: str,
    ui_prefs,
    *,
    progress_sink: str = "cli",
    mode: str | None = None,
    allow_fallbacks: bool | None = None,
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
    resolved_config = InventoryConfig.from_env()
    if allow_fallbacks is None:
        allow_fallbacks = allow_inventory_fallbacks()
    resolved_config.allow_fallbacks = bool(allow_fallbacks)
    mode = (mode or os.getenv("SCYTALEDROID_INVENTORY_MODE", "baseline")).lower().strip()
    progress_cb = None
    if progress_sink == "cli":
        progress.render_snapshot_block(
            meta,
            ui_prefs=ui_prefs,
            mode=mode,
            serial=serial,
            allow_fallbacks=resolved_config.allow_fallbacks,
        )
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
        run_id=f"INV-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}",
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

    # Fallback messaging is handled by the inventory progress preamble to keep
    # the run output visually coherent (single panel).

    try:
        result = runner.run_full_sync(
            serial=serial,
            filter_fn=None,
            progress_cb=progress_cb,
            mode=mode,
            config=resolved_config,
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
        views.print_inventory_run_summary_from_result(result)
        # Keep CLI output minimal; follow-on actions are driven by menu flow.

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
            "fallback_used": getattr(result, "fallback_used", False),
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


def run_scoped_sync(
    *,
    serial: str,
    packages: set[str],
    scope_id: str,
    ui_prefs,
    progress_sink: str = "cli",
    mode: str | None = None,
    allow_fallbacks: bool | None = None,
) -> runner.InventoryResult:
    """Run a scoped inventory sync for a small package set (filesystem-only)."""

    if not serial:
        raise InventoryServiceError("No device serial provided for inventory sync.")
    if not packages:
        raise InventoryServiceError("No packages provided for scoped inventory sync.")

    meta = snapshot_io.load_latest_snapshot_meta(serial)
    resolved_config = InventoryConfig.from_env()
    if allow_fallbacks is None:
        allow_fallbacks = allow_inventory_fallbacks()
    resolved_config.allow_fallbacks = bool(allow_fallbacks)
    mode = (mode or os.getenv("SCYTALEDROID_INVENTORY_MODE", "baseline")).lower().strip()

    progress_cb = None
    if progress_sink == "cli":
        # Reuse the snapshot block for consistent UX, but make it explicit that this is scoped.
        progress.render_snapshot_block(
            meta,
            ui_prefs=ui_prefs,
            mode=f"{mode} (scoped:{scope_id})",
            serial=serial,
            allow_fallbacks=resolved_config.allow_fallbacks,
        )
        progress_cb = progress.make_cli_progress_printer(ui_prefs=ui_prefs)

    try:
        result = runner.run_scoped_sync(
            serial=serial,
            package_allowlist={str(p).strip().lower() for p in packages if str(p).strip()},
            scope_id=str(scope_id),
            progress_cb=progress_cb,
            mode=mode,
            config=resolved_config,
        )
    except InventoryCollectionError as exc:  # pragma: no cover
        completed = max(0, exc.index - 1)
        msg = (
            f"Scoped inventory sync failed for {serial}: package={exc.package} "
            f"stage={exc.stage} progress={completed}/{exc.total}."
        )
        print(status_messages.status(msg, level="error"))
        raise InventoryServiceError(msg) from exc
    except Exception as exc:  # pragma: no cover
        msg = f"Scoped inventory sync failed for {serial}: {exc}."
        print(status_messages.status(msg, level="error"))
        raise InventoryServiceError(msg) from exc

    if progress_sink == "cli":
        views.print_inventory_run_summary_from_result(result)
    return result
