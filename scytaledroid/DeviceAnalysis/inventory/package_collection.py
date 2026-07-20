"""ADB package collection and enrichment (UI-free)."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from scytaledroid.Database.db_utils.package_utils import normalize_package_name
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .. import inventory_meta
from . import adb_bulk, adb_client, normalizer, snapshot_io
from .errors import InventoryCollectionError


class ProgressCallback(Protocol):
    def __call__(
        self,
        processed: int,
        total: int,
        elapsed_seconds: float,
        eta_seconds: float | None,
        split_apks: int,
        *,
        current_package: str | None = None,
        current_stage: str | None = None,
        bulk_rows_completed: int | None = None,
        path_calls_completed: int | None = None,
        metadata_calls_completed: int | None = None,
        active: bool = False,
    ) -> None:
        ...


# Keep PackageRow as a loose alias for the normalized dict shape used throughout
PackageRow = dict[str, object]
InventoryFilter = Callable[[PackageRow], bool]

_TARGET_RESEARCH_PROFILES = frozenset(
    {
        "SOCIAL",
        "MESSAGING",
        "MEDIA",
        "BROWSER",
        "PRODUCTIVITY",
        "SHOPPING",
        "NEWS",
    }
)
# Live Android 15 validation on the research device showed that one bulk
# `dumpsys package packages` call is materially faster than per-package `pm dump`
# even for single-package and small profile refreshes, so baseline inventory
# should preload bulk metadata for any non-empty cohort.
_BASELINE_BULK_METADATA_THRESHOLD = 1


def _is_bulk_path_relevant_for_enrichment(
    package_name: str,
    *,
    canonical_entry: dict[str, object] | None,
    bulk_base_path: str | None,
) -> bool:
    base_path = str(bulk_base_path or "").strip()
    if base_path.startswith("/data/"):
        return True
    if not canonical_entry:
        return False
    profile_key = str(canonical_entry.get("profile_key") or "").strip().upper()
    if profile_key in _TARGET_RESEARCH_PROFILES:
        return True
    return False


def _bulk_metadata_is_complete(metadata: dict[str, object] | None) -> bool:
    if not metadata:
        return False
    required_fields = ("version_name", "last_update", "first_install", "user_id")
    for field in required_fields:
        value = str(metadata.get(field) or "").strip()
        if not value:
            return False
    return True


def _has_full_path_fidelity(row: dict[str, object]) -> bool:
    return str(row.get("path_fidelity") or "").strip() in {
        "pm_path",
        "dumpsys_reconstructed",
        "bulk_single_path",
    }


@dataclass
class CollectionStats:
    total_packages: int
    split_packages: int
    new_packages: int
    removed_packages: int
    elapsed_seconds: float
    path_enriched_packages: int = 0
    bulk_identity_only_packages: int = 0
    package_hash: str | None = None
    package_list_hash: str | None = None
    package_signature_hash: str | None = None
    build_fingerprint: str | None = None
    fallback_used: bool = False
    identity_source: str = "pm_list_show_versioncode"
    identity_quality: str = "strict"
    collection_mode: str = "baseline"


def collect_inventory(
    serial: str,
    *,
    filter_fn: InventoryFilter | None = None,
    package_allowlist: set[str] | None = None,
    progress_cb: ProgressCallback | None = None,
    use_bulk: bool | None = None,
    allow_fallbacks: bool = False,
) -> tuple[list[PackageRow], CollectionStats]:
    """
    Collect inventory rows from ADB and enrich them with canonical metadata.

    This function is UI-free. Progress updates are emitted only via *progress_cb*.
    """
    run_start = time.time()

    adb_client.clear_package_caches(serial)

    packages_with_versions, package_names, bulk_used, fallback_used = adb_client.list_packages(
        serial, use_bulk, allow_fallbacks=allow_fallbacks
    )
    total = len(package_names)

    bulk_entry_map: dict[str, object] = {}
    should_preload_bulk_entries = bulk_used or total >= _BASELINE_BULK_METADATA_THRESHOLD
    if should_preload_bulk_entries:
        try:
            bulk_entry_map = {
                (
                    normalize_package_name(entry.package_name, context="inventory")
                    or entry.package_name.strip().lower()
                ): entry
                for entry in adb_client.list_package_bulk_entries(serial)
                if entry.package_name
            }
        except Exception as exc:
            log.warning(f"Failed to reload bulk package metadata: {exc}", category="inventory")
            bulk_entry_map = {}
    if not packages_with_versions:
        raise RuntimeError("adb did not return any packages.")
    if fallback_used:
        if not allow_fallbacks:
            raise RuntimeError(
                "Inventory fallback blocked (per-package listing). "
                "Enable inventory fallbacks in the Device Analysis menu to proceed."
            )
        log.warning(
            "Inventory fallback used (per-package listing). Results are valid but slower; "
            "ensure non-root fallback is expected.",
            category="inventory",
            extra={
                "event": "inventory.fallback",
                "reason": "per_package_list",
                "serial": serial,
            },
        )

    allowlist = {normalize_package_name(p, context="inventory") or str(p).strip().lower() for p in (package_allowlist or set()) if str(p).strip()}
    if allowlist:
        # Filter early (before per-package metadata/path calls) for speed.
        filtered_names: list[str] = []
        for pkg in package_names:
            canon = normalize_package_name(pkg, context="inventory") or pkg.strip().lower()
            if canon in allowlist:
                filtered_names.append(pkg)
        package_names = filtered_names
        filtered_with_versions = []
        for pkg, version_code, third in packages_with_versions:
            canon = normalize_package_name(pkg, context="inventory") or str(pkg).strip().lower()
            if canon in allowlist:
                filtered_with_versions.append((pkg, version_code, third))
        packages_with_versions = filtered_with_versions

    _emit_progress(progress_cb, processed=0, total=total, elapsed=0.0, eta=None, split_apks=0)

    device_properties = adb_client.get_device_properties(serial)
    fingerprint = device_properties.get("build_fingerprint") if device_properties else None

    # Load canonical metadata from DB so category/profile tagging and scopes work.
    canonical_metadata: dict[str, dict[str, object]] = {}
    try:
        if package_names:
            canonical_metadata = snapshot_io.load_canonical_metadata(package_names) or {}
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(f"Failed to load canonical metadata: {exc}", category="inventory")
        canonical_metadata = {}

    rows: list[dict[str, object]] = []
    version_by_package: dict[str, str] = {}
    degraded_identity = False
    for package_name, version_code, _ in packages_with_versions:
        canonical_name = normalize_package_name(package_name, context="inventory") or package_name.strip().lower()
        if not canonical_name:
            continue
        if isinstance(version_code, str) and version_code.strip():
            version_by_package[canonical_name] = version_code.strip()

    dumpsys_metadata_map: dict[str, dict[str, object]] = {}
    should_preload_dumpsys_metadata = bulk_used or total >= _BASELINE_BULK_METADATA_THRESHOLD
    if should_preload_dumpsys_metadata:
        try:
            dumpsys_metadata_map = {
                (
                    normalize_package_name(package_name, context="inventory")
                    or package_name.strip().lower()
                ): dict(metadata)
                for package_name, metadata in adb_client.get_package_metadata_bulk(serial).items()
                if package_name
            }
        except Exception as exc:
            log.warning(
                f"Failed to preload baseline inventory metadata from dumpsys package packages: {exc}",
                category="inventory",
            )
            dumpsys_metadata_map = {}

    # Progress cadence: for small scoped cohorts (e.g., paper profiles with ~19-21 packages),
    # emit every package. For full-device runs, target roughly 40 visible completions so the
    # operator sees regular forward motion even on slow non-root devices.
    if total <= 50:
        progress_interval = 1
    else:
        progress_interval = max(10, total // 40 or 1)
    scan_start = time.time()
    split_processed = 0
    profile_enabled = os.getenv("SCYTALEDROID_INVENTORY_PROFILE", "0").strip() in {"1", "true", "yes", "on"}
    profile_calls_paths = 0
    profile_calls_metadata = 0
    profile_bulk_rows = 0
    profile_pkg_timings: list[dict[str, object]] = []

    for index, package_name in enumerate(package_names, start=1):
        t0 = time.time()
        stage = "bulk"
        package_key = normalize_package_name(package_name, context="inventory") or package_name.lower()
        canonical_entry = canonical_metadata.get(package_key)
        try:
            if bulk_used:
                _emit_progress(
                    progress_cb,
                    processed=index - 1,
                    total=total,
                    elapsed=time.time() - scan_start,
                    eta=None,
                    split_apks=split_processed,
                    current_package=package_name,
                    current_stage="bulk",
                    bulk_rows_completed=profile_bulk_rows,
                    path_calls_completed=profile_calls_paths,
                    metadata_calls_completed=profile_calls_metadata,
                    active=True,
                )
                bulk_entry = bulk_entry_map.get(package_key)
                bulk_dump_metadata = dict(dumpsys_metadata_map.get(package_key) or {})
                reconstructed_paths = adb_bulk.reconstruct_apk_paths(bulk_dump_metadata)
                bulk_base_path = str(getattr(bulk_entry, "apk_path", "")).strip() or None
                # If the package is present in the authoritative bulk version list but
                # missing from the parsed bulk-entry map, prefer `pm path` over
                # silently recording a sparse row. That keeps parser gaps from
                # masquerading as real `no_paths` device state.
                should_enrich_paths = bulk_entry is None or _is_bulk_path_relevant_for_enrichment(
                    package_name,
                    canonical_entry=canonical_entry,
                    bulk_base_path=bulk_base_path,
                )
                if should_enrich_paths:
                    if reconstructed_paths:
                        paths = reconstructed_paths
                        path_fidelity = "dumpsys_reconstructed"
                        t_paths = time.time() - t0
                    else:
                        stage = "paths"
                        _emit_progress(
                            progress_cb,
                            processed=index - 1,
                            total=total,
                            elapsed=time.time() - scan_start,
                            eta=None,
                            split_apks=split_processed,
                            current_package=package_name,
                            current_stage="pm path",
                            bulk_rows_completed=profile_bulk_rows,
                            path_calls_completed=profile_calls_paths,
                            metadata_calls_completed=profile_calls_metadata,
                            active=True,
                        )
                        paths = adb_client.get_package_paths(
                            serial, package_name, allow_fallbacks=allow_fallbacks
                        )
                        path_fidelity = "pm_path"
                        t_paths = time.time() - t0
                        profile_calls_paths += 1
                else:
                    paths = [bulk_base_path] if bulk_base_path else []
                    path_fidelity = "bulk_base_only"
                    t_paths = time.time() - t0
                metadata = {
                    "package_name": package_name,
                    "installer": getattr(bulk_entry, "installer", None),
                    "version_code": getattr(bulk_entry, "version_code", None),
                    "user_id": str(bulk_entry.uid) if getattr(bulk_entry, "uid", None) is not None else None,
                    "path_fidelity": path_fidelity,
                }
                metadata.update(bulk_dump_metadata)
                metadata["path_fidelity"] = path_fidelity
                t_meta = 0.0
                profile_bulk_rows += 1
            else:
                bulk_metadata = dict(dumpsys_metadata_map.get(package_key) or {})
                bulk_entry = bulk_entry_map.get(package_key)
                bulk_base_path = str(getattr(bulk_entry, "apk_path", "")).strip() or None
                reconstructed_paths = adb_bulk.reconstruct_apk_paths(bulk_metadata)
                path_fidelity = "dumpsys_reconstructed"
                if reconstructed_paths:
                    paths = reconstructed_paths
                    t_paths = time.time() - t0
                elif bulk_base_path:
                    paths = [bulk_base_path]
                    t_paths = time.time() - t0
                    path_fidelity = "bulk_single_path"
                else:
                    _emit_progress(
                        progress_cb,
                        processed=index - 1,
                        total=total,
                        elapsed=time.time() - scan_start,
                        eta=None,
                        split_apks=split_processed,
                        current_package=package_name,
                        current_stage="pm path",
                        bulk_rows_completed=None,
                        path_calls_completed=profile_calls_paths,
                        metadata_calls_completed=profile_calls_metadata,
                        active=True,
                    )
                    paths = adb_client.get_package_paths(
                        serial, package_name, allow_fallbacks=allow_fallbacks
                    )
                    t_paths = time.time() - t0
                    profile_calls_paths += 1
                    path_fidelity = "pm_path"
                if bulk_metadata:
                    bulk_metadata.setdefault("package_name", package_name)
                bulk_metadata["path_fidelity"] = path_fidelity
                should_enrich_deep_metadata = not _bulk_metadata_is_complete(bulk_metadata)
                if should_enrich_deep_metadata:
                    stage = "metadata"
                    _emit_progress(
                        progress_cb,
                        processed=index - 1,
                        total=total,
                        elapsed=time.time() - scan_start,
                        eta=None,
                        split_apks=split_processed,
                        current_package=package_name,
                        current_stage="pm dump",
                        bulk_rows_completed=None,
                        path_calls_completed=profile_calls_paths,
                        metadata_calls_completed=profile_calls_metadata,
                        active=True,
                    )
                    metadata = bulk_metadata
                    metadata.update(adb_client.get_package_metadata(serial, package_name))
                    metadata["path_fidelity"] = path_fidelity
                    t_meta = time.time() - t0 - t_paths
                else:
                    metadata = bulk_metadata or {"package_name": package_name}
                    t_meta = 0.0
        except Exception as exc:
            raise InventoryCollectionError(
                package=package_name, index=index, total=total, stage=stage, original=exc
            ) from exc
        if not bulk_used and t_meta > 0.0:
            profile_calls_metadata += 1
        entry = normalizer.compose_inventory_entry(package_name, paths, metadata, canonical_entry)
        canonical_name = str(entry.get("package_name") or "").strip().lower()
        authoritative_version_code = version_by_package.get(canonical_name)
        if authoritative_version_code:
            entry["version_code"] = authoritative_version_code
            entry["identity_quality"] = "strict"
            entry["identity_source"] = "pm_list_show_versioncode"
        else:
            degraded_identity = True
            entry["identity_quality"] = "degraded"
            entry["identity_source"] = "fallback"

        if filter_fn and not filter_fn(entry):
            continue

        rows.append(entry)

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
                current_package=package_name,
                current_stage="complete",
                bulk_rows_completed=profile_bulk_rows if bulk_used else None,
                path_calls_completed=profile_calls_paths,
                metadata_calls_completed=profile_calls_metadata if not bulk_used else None,
            )
        if profile_enabled:
            try:
                log.debug(
                    f"[inv.profile] {index}/{total} pkg={package_name} splits={normalizer.split_count(entry)} "
                    f"t_paths={t_paths:.3f}s t_meta={t_meta:.3f}s t_pkg={(time.time()-t0):.3f}s "
                    f"bulk_row={'yes' if bulk_used else 'no'}",
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
                f"[inv.profile] total_pkgs={len(rows)} bulk_rows={profile_bulk_rows} "
                f"calls_paths={profile_calls_paths} calls_metadata={profile_calls_metadata} "
                f"elapsed_total={elapsed_total:.2f}s",
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

    normalized_package_names = [
        normalize_package_name(name, context="inventory") or str(name).strip().lower()
        for name in package_names
        if str(name).strip()
    ]

    package_hash = snapshot_io.hash_rows(rows)
    package_list_hash = inventory_meta.compute_name_hash(normalized_package_names)
    package_signature_hash = inventory_meta.compute_signature_hash(
        inventory_meta.snapshot_signatures(rows)
    )

    stats = CollectionStats(
        total_packages=len(rows),
        split_packages=split_processed,
        new_packages=0,  # computed in runner using previous snapshot
        removed_packages=0,  # computed in runner using previous snapshot
        elapsed_seconds=elapsed_total,
        path_enriched_packages=sum(1 for row in rows if _has_full_path_fidelity(row)),
        bulk_identity_only_packages=sum(1 for row in rows if row.get("path_fidelity") == "bulk_base_only"),
        package_hash=package_hash,
        package_list_hash=package_list_hash,
        package_signature_hash=package_signature_hash,
        build_fingerprint=fingerprint,
        fallback_used=fallback_used,
        identity_source="pm_list_show_versioncode" if not fallback_used else "fallback",
        identity_quality="degraded" if degraded_identity else "strict",
        collection_mode="bulk" if bulk_used else "baseline",
    )

    return rows, stats


def _emit_progress(
    callback: ProgressCallback | None,
    *,
    processed: int,
    total: int,
    elapsed: float,
    eta: float | None,
    split_apks: int,
    current_package: str | None = None,
    current_stage: str | None = None,
    bulk_rows_completed: int | None = None,
    path_calls_completed: int | None = None,
    metadata_calls_completed: int | None = None,
    active: bool = False,
) -> None:
    if not callback:
        return
    try:
        callback(
            processed,
            total,
            elapsed,
            eta,
            split_apks,
            current_package=current_package,
            current_stage=current_stage,
            bulk_rows_completed=bulk_rows_completed,
            path_calls_completed=path_calls_completed,
            metadata_calls_completed=metadata_calls_completed,
            active=active,
        )
    except Exception as exc:  # pragma: no cover - defensive logging
        log.warning(f"Progress callback raised {exc}", category="inventory")
