"""Orchestration engine for inventory sync (UI-free)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Protocol

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
    rows: list
    stats: InventorySyncStats
    previous_total: Optional[int]
    previous_split: Optional[int]
    synced_app_definitions: int
    elapsed_seconds: float


def run_full_sync(
    serial: str,
    filter_fn: Optional[Callable[[Dict[str, object]], bool]] = None,
    progress_cb: Optional[ProgressCallback] = None,
) -> InventoryResult:
    """
    Run a full inventory sync for *serial* and return a UI-free result.
    """
    prev_meta = snapshot_io.load_latest_snapshot_meta(serial)
    prev_snapshot = snapshot_io.load_latest_inventory(serial)
    prev_packages: set[str] = set()
    prev_split = 0
    if prev_snapshot:
        pkgs = prev_snapshot.get("packages") or []
        if isinstance(pkgs, list):
            for item in pkgs:
                if isinstance(item, dict):
                    name = item.get("package_name")
                    if isinstance(name, str):
                        prev_packages.add(name)
                    if int(item.get("split_count") or 1) > 1:
                        prev_split += 1

    rows, coll_stats = package_collection.collect_inventory(
        serial=serial,
        filter_fn=filter_fn,
        progress_cb=progress_cb,
    )

    snapshot_path = snapshot_io.persist_snapshot(
        serial=serial,
        rows=rows,  # type: ignore[arg-type]
        package_hash=coll_stats.package_hash,
        package_list_hash=coll_stats.package_list_hash,
        package_signature_hash=coll_stats.package_signature_hash,
        build_fingerprint=coll_stats.build_fingerprint,
        duration_seconds=coll_stats.elapsed_seconds,
        snapshot_type="full",
    )

    synced_defs = db_sync.sync_app_definitions(rows)

    current_pkg_names: set[str] = set()
    split_count = 0
    for item in rows:
        if isinstance(item, dict):
            name = item.get("package_name")
            if isinstance(name, str):
                current_pkg_names.add(name)
            if int(item.get("split_count") or 1) > 1:
                split_count += 1

    new_pkgs = len(current_pkg_names - prev_packages) if prev_packages else len(current_pkg_names)
    removed_pkgs = len(prev_packages - current_pkg_names) if prev_packages else 0

    stats = InventorySyncStats(
        total_packages=len(current_pkg_names),
        split_packages=split_count,
        new_packages=new_pkgs,
        removed_packages=removed_pkgs,
        elapsed_seconds=coll_stats.elapsed_seconds,
    )

    return InventoryResult(
        serial=serial,
        snapshot_path=snapshot_path,
        rows=rows,
        stats=stats,
        previous_total=(prev_meta.package_count if prev_meta else None),
        previous_split=prev_split if prev_split else None,
        synced_app_definitions=synced_defs,
        elapsed_seconds=coll_stats.elapsed_seconds,
    )
