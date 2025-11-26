"""Orchestration engine for inventory sync (UI-free)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol

from scytaledroid.DeviceAnalysis.inventory import snapshot_io
from scytaledroid.DeviceAnalysis.inventory import package_collection
from scytaledroid.DeviceAnalysis.inventory import db_sync


class ProgressCallback(Protocol):
    def __call__(
        self,
        processed: int,
        total: int,
        elapsed_seconds: float,
        eta_seconds: Optional[float],
        split_apks: int,
    ) -> None:
        ...


@dataclass
class InventorySyncStats:
    total_packages: int
    split_packages: int
    new_packages: int
    removed_packages: int
    elapsed_seconds: float


@dataclass
class InventoryResult:
    serial: str
    snapshot_path: Path
    stats: InventorySyncStats
    previous_total: Optional[int]
    previous_split: Optional[int]
    synced_app_definitions: int
    elapsed_seconds: float


def run_full_sync(
    serial: str,
    filter_fn: Optional[Callable[[package_collection.PackageRow], bool]] = None,
    progress_cb: Optional[ProgressCallback] = None,
) -> InventoryResult:
    """
    Run a full inventory sync for *serial* and return a UI-free result.
    """
    # Legacy-compatible path: delegate to the existing run_inventory_sync but
    # suppress interactive UI. Then derive stats from the latest snapshot.
    prev_meta = snapshot_io.load_latest_snapshot_meta(serial)
    prev_packages: set[str] = set()
    prev_split: Optional[int] = None
    if prev_meta:
        latest_prev = snapshot_io.load_latest_inventory(serial)
        if latest_prev:
            pkgs = latest_prev.get("packages") or []
            if isinstance(pkgs, list):
                for item in pkgs:
                    if isinstance(item, dict) and isinstance(item.get("package_name"), str):
                        prev_packages.add(item["package_name"])
                prev_split = sum(1 for item in pkgs if isinstance(item, dict) and int(item.get("split_count") or 1) > 1)

    # Call legacy sync (non-interactive) to perform the actual work.
    from scytaledroid.DeviceAnalysis import inventory as legacy_inventory

    legacy_inventory.run_inventory_sync(
        serial,
        filter_fn=filter_fn,
        interactive=False,
        progress_callback=progress_cb,
    )

    latest_meta = snapshot_io.load_latest_snapshot_meta(serial)
    latest_payload = snapshot_io.load_latest_inventory(serial) or {}
    pkgs = latest_payload.get("packages") or []
    pkg_names: set[str] = set()
    split_count = 0
    if isinstance(pkgs, list):
        for item in pkgs:
            if isinstance(item, dict):
                name = item.get("package_name")
                if isinstance(name, str):
                    pkg_names.add(name)
                if int(item.get("split_count") or 1) > 1:
                    split_count += 1

    new_pkgs = len(pkg_names - prev_packages) if prev_packages else len(pkg_names)
    removed_pkgs = len(prev_packages - pkg_names) if prev_packages else 0

    stats = InventorySyncStats(
        total_packages=len(pkg_names),
        split_packages=split_count,
        new_packages=new_pkgs,
        removed_packages=removed_pkgs,
        elapsed_seconds=float(getattr(latest_meta, "duration_seconds", 0.0) or 0.0),
    )

    return InventoryResult(
        serial=serial,
        snapshot_path=Path(latest_payload.get("snapshot_path") or ""),
        stats=stats,
        previous_total=(prev_meta.package_count if prev_meta else None),
        previous_split=prev_split,
        synced_app_definitions=0,
        elapsed_seconds=stats.elapsed_seconds,
    )
