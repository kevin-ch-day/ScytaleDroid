"""ADB package collection and enrichment (UI-free)."""

from __future__ import annotations

import time
import os
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Protocol

from scytaledroid.Utils.LoggingUtils import logging_utils as log
from .. import inventory_meta
from . import snapshot_io
from . import adb_client, normalizer
from .errors import InventoryCollectionError

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


# Keep PackageRow as a loose alias for the normalized dict shape used throughout
PackageRow = Dict[str, object]


@dataclass
class CollectionStats:
    total_packages: int
    split_packages: int
    new_packages: int
    removed_packages: int
    elapsed_seconds: float
    package_hash: Optional[str] = None
    package_list_hash: Optional[str] = None
    package_signature_hash: Optional[str] = None
    build_fingerprint: Optional[str] = None


def collect_inventory(
    serial: str,
    *,
    filter_fn: Optional[Callable[[Dict[str, object]], bool]] = None,
    progress_cb: Optional[ProgressCallback] = None,
    use_bulk: Optional[bool] = None,
) -> Tuple[List[PackageRow], CollectionStats]:
    """
    Collect inventory rows from ADB and enrich them with canonical metadata.

    This function is UI-free. Progress updates are emitted only via *progress_cb*.
    """
    run_start = time.time()

    adb_client.clear_package_caches(serial)

    packages_with_versions, package_names, _ = adb_client.list_packages(serial, use_bulk)
    if not packages_with_versions:
        raise RuntimeError("adb did not return any packages.")

    total = len(package_names)

    _emit_progress(progress_cb, processed=0, total=total, elapsed=0.0, eta=None, split_apks=0)

    device_properties = adb_client.get_device_properties(serial)
    fingerprint = device_properties.get("build_fingerprint") if device_properties else None

    # Load canonical metadata from DB so category/profile tagging and scopes work.
    canonical_metadata: Dict[str, Dict[str, object]] = {}
    try:
        if package_names:
            canonical_metadata = snapshot_io.load_canonical_metadata(package_names) or {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(f"Failed to load canonical metadata: {exc}", category="inventory")
        canonical_metadata = {}

    rows: List[Dict[str, object]] = []
    package_definitions: Dict[str, Optional[str]] = {}
    progress_interval = max(20, total // 20 or 1)
    scan_start = time.time()
    split_processed = 0
    profile_enabled = os.getenv("SCYTALEDROID_INVENTORY_PROFILE", "0").strip() in {"1", "true", "yes", "on"}
    profile_calls_paths = 0
    profile_calls_meta = 0
    profile_pkg_timings: List[Dict[str, object]] = []

    for index, package_name in enumerate(package_names, start=1):
        # For correctness, always fetch full metadata/paths per package for now.
        t0 = time.time()
        stage = "paths"
        try:
            paths = adb_client.get_package_paths(serial, package_name)
            t_paths = time.time() - t0
            stage = "metadata"
            metadata = adb_client.get_package_metadata(serial, package_name)
            t_meta = time.time() - t0 - t_paths
        except Exception as exc:
            raise InventoryCollectionError(
                package=package_name, index=index, total=total, stage=stage, original=exc
            ) from exc
        profile_calls_paths += 1
        profile_calls_meta += 1
        package_key = package_name.lower()
        canonical_entry = canonical_metadata.get(package_key)
        entry = normalizer.compose_inventory_entry(package_name, paths, metadata, canonical_entry)

        if filter_fn and not filter_fn(entry):
            continue

        rows.append(entry)
        normalized_key = str(entry.get("package_name") or package_name).lower()
        app_label = entry.get("app_label")
        package_definitions.setdefault(normalized_key, app_label if isinstance(app_label, str) else None)

        if normalizer.split_count(entry) > 1:
            split_processed += 1

        if index % progress_interval == 0 or index == total:
            elapsed = time.time() - scan_start
            estimated_total = (elapsed / index) * total if index else None
            eta = (estimated_total - elapsed) if estimated_total and estimated_total > elapsed else None
            _emit_progress(
                progress_cb,
                processed=index,
                total=total,
                elapsed=elapsed,
                eta=eta,
                split_apks=split_processed,
            )
        if profile_enabled:
            try:
                log.debug(
                    f"[inv.profile] {index}/{total} pkg={package_name} splits={normalizer.split_count(entry)} "
                    f"t_paths={t_paths:.3f}s t_meta={t_meta:.3f}s t_pkg={(time.time()-t0):.3f}s",
                    category="inventory",
                )
                profile_pkg_timings.append(
                    {
                        "pkg": package_name,
                        "t_paths": t_paths,
                        "t_meta": t_meta,
                        "t_total": time.time() - t0,
                        "split_count": normalizer.split_count(entry),
                    }
                )
            except Exception:
                pass

    elapsed_total = time.time() - run_start
    if profile_enabled:
        try:
            log.info(
                f"[inv.profile] total_pkgs={len(rows)} calls_paths={profile_calls_paths} "
                f"calls_meta={profile_calls_meta} elapsed_total={elapsed_total:.2f}s",
                category="inventory",
            )
            if profile_pkg_timings:
                top_total = sorted(profile_pkg_timings, key=lambda r: r["t_total"], reverse=True)[:10]
                top_paths = sorted(profile_pkg_timings, key=lambda r: r["t_paths"], reverse=True)[:10]
                top_meta = sorted(profile_pkg_timings, key=lambda r: r["t_meta"], reverse=True)[:10]
                log.info(
                    f"[inv.profile.top] total={[(r['pkg'], round(r['t_total'],3)) for r in top_total]}",
                    category="inventory",
                )
                log.info(
                    f"[inv.profile.top_paths] paths={[(r['pkg'], round(r['t_paths'],3)) for r in top_paths]}",
                    category="inventory",
                )
                log.info(
                    f"[inv.profile.top_meta] meta={[(r['pkg'], round(r['t_meta'],3)) for r in top_meta]}",
                    category="inventory",
                )
        except Exception:
            pass

    package_hash = snapshot_io.hash_rows(rows)
    package_list_hash = inventory_meta.compute_name_hash(package_names)
    package_signature_hash = inventory_meta.compute_signature_hash(
        inventory_meta.snapshot_signatures(rows)
    )

    stats = CollectionStats(
        total_packages=len(rows),
        split_packages=split_processed,
        new_packages=0,  # computed in runner using previous snapshot
        removed_packages=0,  # computed in runner using previous snapshot
        elapsed_seconds=elapsed_total,
        package_hash=package_hash,
        package_list_hash=package_list_hash,
        package_signature_hash=package_signature_hash,
        build_fingerprint=fingerprint,
    )

    return rows, stats


# --- Helpers copied from legacy inventory.py (UI-free) ---

def _emit_progress(
    callback: ProgressCallback | None,
    *,
    processed: int,
    total: int,
    elapsed: float,
    eta: Optional[float],
    split_apks: int,
) -> None:
    if not callback:
        return
    try:
        callback(processed, total, elapsed, eta, split_apks)
    except Exception as exc:  # pragma: no cover - defensive logging
        log.warning(f"Progress callback raised {exc}", category="inventory")


def _split_count(entry: Dict[str, object]) -> int:
    """Compatibility wrapper around normalizer.split_count for tests."""
    return normalizer.split_count(entry)


def _compose_inventory_entry(
    package_name: str,
    paths: List[str],
    metadata: Dict[str, Optional[str]],
    canonical: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    """Compatibility wrapper around normalizer.compose_inventory_entry for tests."""
    return normalizer.compose_inventory_entry(package_name, paths, metadata, canonical)
