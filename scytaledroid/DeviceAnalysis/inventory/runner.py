"""Orchestration engine for inventory sync (UI-free)."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from scytaledroid.DeviceAnalysis.inventory import db_sync, package_collection, snapshot_io
from scytaledroid.DeviceAnalysis.modes.inventory import InventoryConfig, InventoryMode
from scytaledroid.Database.db_utils.package_utils import normalize_package_name
from scytaledroid.Utils.LoggingUtils import logging_utils as log


class ProgressCallback(Protocol):
    """Receives progress events as dicts (phase/progress/complete)."""

    def __call__(self, event: dict[str, object]) -> None:
        ...


@dataclass
class InventorySyncStats:
    total_packages: int
    split_packages: int
    elapsed_seconds: float
    fallback_used: bool = False


@dataclass
class InventoryDelta:
    new_count: int
    removed_count: int
    updated_count: int
    changed_packages_count: int


@dataclass
class InventoryResult:
    serial: str
    snapshot_path: Path
    snapshot_id: int | None
    expected_rows: int
    persisted_rows: int
    rows: list
    stats: InventorySyncStats
    fallback_used: bool
    previous_total: int | None
    previous_split: int | None
    synced_app_definitions: int
    elapsed_seconds: float
    delta: InventoryDelta
    first_snapshot: bool


def run_full_sync(
    serial: str,
    filter_fn: Callable[[dict[str, object | None], bool]] = None,
    progress_cb: ProgressCallback | None = None,
    mode: str | None = None,
    config: InventoryConfig | None = None,
) -> InventoryResult:
    """
    Run a full inventory sync for *serial* and return a UI-free result.
    """
    prev_meta = snapshot_io.load_latest_snapshot_meta(serial)
    prev_snapshot = snapshot_io.load_latest_inventory(serial)
    prev_packages: set[str] = set()
    prev_identity: dict[str, str | None] = {}
    prev_split = 0
    if prev_snapshot:
        pkgs = prev_snapshot.get("packages") or []
        if isinstance(pkgs, list):
            for item in pkgs:
                if isinstance(item, dict):
                    name = item.get("package_name")
                    if isinstance(name, str):
                        cleaned = normalize_package_name(name, context="inventory")
                        if cleaned:
                            prev_packages.add(cleaned)
                            version_code = item.get("version_code")
                            if isinstance(version_code, (int, str)):
                                prev_identity[cleaned] = str(version_code)
                            else:
                                prev_identity[cleaned] = None
                    if int(item.get("split_count") or 1) > 1:
                        prev_split += 1

    # Adapt the collector's numeric progress callback to dict-based callbacks expected by CLI.
    def _progress_adapter(
        processed: int,
        total: int,
        elapsed_seconds: float,
        eta_seconds: float | None,
        split_apks: int,
    ) -> None:
        if progress_cb:
            progress_cb(
                {
                    "phase": "progress",
                    "phase_label": "Collecting packages",
                    "processed": processed,
                    "total": total,
                    "elapsed_seconds": elapsed_seconds,
                    "eta_seconds": eta_seconds,
                    "split_processed": split_apks,
                }
            )

    if progress_cb:
        progress_cb({"phase": "start", "total": None, "phase_label": "Collecting packages"})

    # Resolve mode/config once and keep it consistent for the run.
    resolved_config = config or InventoryConfig.from_env()
    mode = (mode or resolved_config.mode.value).lower().strip()
    effective_filter = filter_fn
    if mode == InventoryMode.USER_ONLY.value:
        def _user_only(entry: dict[str, object]) -> bool:
            primary_path = str(entry.get("primary_path") or "")
            return primary_path.startswith("/data/")
        effective_filter = _user_only if filter_fn is None else lambda entry: filter_fn(entry) and _user_only(entry)

    collect_start = time.time()
    rows, coll_stats = package_collection.collect_inventory(
        serial=serial,
        filter_fn=effective_filter,
        progress_cb=_progress_adapter if progress_cb else None,
        allow_fallbacks=resolved_config.allow_fallbacks,
    )
    collect_elapsed = time.time() - collect_start

    # Build package name maps for delta computation.
    current_pkg_names: set[str] = set()
    current_identity: dict[str, str | None] = {}
    split_count = 0
    for item in rows:
        if isinstance(item, dict):
            name = item.get("package_name")
            if isinstance(name, str):
                cleaned = normalize_package_name(name, context="inventory")
                if cleaned:
                    current_pkg_names.add(cleaned)
                    version_code = item.get("version_code")
                    if isinstance(version_code, (int, str)):
                        current_identity[cleaned] = str(version_code)
                    else:
                        current_identity[cleaned] = None
            if int(item.get("split_count") or 1) > 1:
                split_count += 1

    stats = InventorySyncStats(
        total_packages=len(current_pkg_names),
        split_packages=split_count,
        elapsed_seconds=coll_stats.elapsed_seconds,
        fallback_used=bool(getattr(coll_stats, "fallback_used", False)),
    )

    # Compute delta vs previous snapshot (single source of truth).
    first_snapshot = not bool(prev_packages)
    new_pkgs = len(current_pkg_names - prev_packages) if prev_packages else len(current_pkg_names)
    removed_pkgs = len(prev_packages - current_pkg_names) if prev_packages else 0

    updated_pkgs = 0
    if prev_packages:
        for name in current_pkg_names & prev_packages:
            if prev_identity.get(name) != current_identity.get(name):
                updated_pkgs += 1

    delta = InventoryDelta(
        new_count=new_pkgs,
        removed_count=removed_pkgs,
        updated_count=updated_pkgs,
        changed_packages_count=new_pkgs + removed_pkgs + updated_pkgs,
    )

    persist_start = time.time()
    persist_result = snapshot_io.persist_snapshot(
        serial=serial,
        rows=rows,  # type: ignore[arg-type]
        package_hash=coll_stats.package_hash,
        package_list_hash=coll_stats.package_list_hash,
        package_signature_hash=coll_stats.package_signature_hash,
        build_fingerprint=coll_stats.build_fingerprint,
        duration_seconds=coll_stats.elapsed_seconds,
        snapshot_type="full",
        collection_stats=coll_stats,
        delta=delta,
    )
    snapshot_path = persist_result.path
    snapshot_id = persist_result.snapshot_id
    persisted_rows = persist_result.persisted_rows
    expected_rows = stats.total_packages
    persist_elapsed = time.time() - persist_start

    db_start = time.time()
    synced_defs = db_sync.sync_app_definitions(rows)
    db_elapsed = time.time() - db_start

    result = InventoryResult(
        serial=serial,
        snapshot_path=snapshot_path,
        snapshot_id=snapshot_id,
        expected_rows=expected_rows,
        persisted_rows=persisted_rows,
        rows=rows,
        stats=stats,
        fallback_used=bool(getattr(coll_stats, "fallback_used", False)),
        previous_total=(prev_meta.package_count if prev_meta else None),
        previous_split=prev_split if prev_split else None,
        synced_app_definitions=synced_defs,
        elapsed_seconds=coll_stats.elapsed_seconds,
        delta=delta,
        first_snapshot=first_snapshot,
    )

    if progress_cb:
        progress_cb(
            {
                "phase": "complete",
                "phase_label": "Collecting packages",
                "total": stats.total_packages,
                "elapsed_seconds": stats.elapsed_seconds,
            }
        )

    overall_elapsed = collect_elapsed + persist_elapsed + db_elapsed
    try:
        per_pkg = overall_elapsed / max(1, stats.total_packages)
        log.info(
            (
                f"Inventory timing for {serial}: {stats.total_packages} packages in "
                f"{overall_elapsed:.2f}s (collect={collect_elapsed:.2f}s, "
                f"snapshot={persist_elapsed:.2f}s, db_sync={db_elapsed:.2f}s, "
                f"~{per_pkg:.2f}s/pkg, mode={mode})"
            ),
            category="inventory",
        )
    except Exception:
        pass

    return result
