"""ADB package collection and enrichment (UI-free)."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable, Dict, List, Optional, Protocol, Tuple

from scytaledroid.Utils.LoggingUtils import logging_utils as log
from .. import adb_utils, package_profiles
from .. import inventory_meta
from . import snapshot_io

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
) -> Tuple[List[PackageRow], CollectionStats]:
    """
    Collect inventory rows from ADB and enrich them with canonical metadata.

    This function is UI-free. Progress updates are emitted only via *progress_cb*.
    """
    run_start = time.time()

    adb_utils.clear_package_caches(serial)
    packages_with_versions = adb_utils.list_packages_with_versions(serial)
    if not packages_with_versions:
        raise RuntimeError("adb did not return any packages.")

    package_names = [entry[0] for entry in packages_with_versions if entry and entry[0]]
    total = len(package_names)

    _emit_progress(progress_cb, processed=0, total=total, elapsed=0.0, eta=None, split_apks=0)

    device_properties = adb_utils.get_basic_properties(serial)
    fingerprint = device_properties.get("build_fingerprint") if device_properties else None

    canonical_metadata = snapshot_io.load_canonical_metadata(package_names)

    rows: List[Dict[str, object]] = []
    package_definitions: Dict[str, Optional[str]] = {}
    progress_interval = max(20, total // 20 or 1)
    scan_start = time.time()
    split_processed = 0

    for index, package_name in enumerate(package_names, start=1):
        paths = adb_utils.get_package_paths(serial, package_name)
        metadata = adb_utils.get_package_metadata(serial, package_name)
        package_key = package_name.lower()
        canonical_entry = canonical_metadata.get(package_key)
        entry = _compose_inventory_entry(package_name, paths, metadata, canonical_entry)

        if filter_fn and not filter_fn(entry):
            continue

        rows.append(entry)
        normalized_key = str(entry.get("package_name") or package_name).lower()
        app_label = entry.get("app_label")
        package_definitions.setdefault(normalized_key, app_label if isinstance(app_label, str) else None)

        if _split_count(entry) > 1:
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

    elapsed_total = time.time() - run_start

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
    value = entry.get("split_count")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            if value.lower() in {"yes", "true"}:
                paths = entry.get("apk_paths")
                if isinstance(paths, list) and paths:
                    return len(paths)
                return 2
    return 1


def _compose_inventory_entry(
    package_name: str,
    paths: List[str],
    metadata: Dict[str, Optional[str]],
    canonical: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    primary_path = paths[0] if paths else ""
    fallback_category, partition = _derive_category(primary_path)
    installer = _normalise_installer(metadata.get("installer"))
    review_needed = canonical is None

    category_id = canonical.get("category_id") if canonical else None
    category_name = canonical.get("category_name") if canonical else None
    heuristic_category = False
    if not category_name:
        category_name = fallback_category
        heuristic_category = True

    profile_id = canonical.get("profile_id") if canonical else None
    profile_name = canonical.get("profile_name") if canonical else None
    heuristic_profile = False
    if not profile_id and not profile_name:
        profile = package_profiles.lookup_profile(package_name)
        profile_id = profile.id if profile else None
        profile_name = profile.name if profile else None
        heuristic_profile = bool(profile_id or profile_name)

    if heuristic_category or heuristic_profile:
        review_needed = True

    source_category = category_name if category_name in _CATEGORY_ORDER else fallback_category
    source = _derive_source(str(source_category or fallback_category), installer)

    app_label = (
        (canonical.get("app_name") if canonical else None)
        or metadata.get("app_label")
        or package_name
    )
    version_name = metadata.get("version_name")
    version_code = metadata.get("version_code")

    split_count = len(paths)
    apk_dirs = sorted({path.rsplit("/", 1)[0] for path in paths if "/" in path})

    entry: Dict[str, object] = {
        "package_name": package_name,
        "app_label": app_label,
        "version_name": version_name,
        "version_code": version_code,
        "installer": installer,
        "first_install": metadata.get("first_install"),
        "last_update": metadata.get("last_update"),
        "primary_path": primary_path,
        "category": category_name,
        "category_name": category_name,
        "category_id": category_id,
        "partition": partition,
        "source": source,
        "profile_id": profile_id,
        "profile_name": profile_name,
        "split_flag": "Yes" if split_count > 1 else "No",
        "apk_paths": paths,
        "apk_dirs": apk_dirs,
        "review_needed": review_needed,
        "inferred_category": heuristic_category,
        "inferred_profile": heuristic_profile,
    }

    entry["split_count"] = split_count  # type: ignore[index]

    return entry


_CATEGORY_ORDER = {
    "User": 0,
    "OEM": 1,
    "System": 2,
    "Mainline": 3,
    "Vendor": 4,
    "Other": 5,
    "Unknown": 6,
}


def _derive_category(primary_path: str) -> Tuple[str, str]:
    if primary_path.startswith("/data/"):
        return "User", "Data (/data)"
    if primary_path.startswith("/product/"):
        return "OEM", "Product (/product)"
    if primary_path.startswith("/system_ext/") or primary_path.startswith("/system/"):
        return "System", "System (/system, /system_ext)"
    if primary_path.startswith("/apex/"):
        return "Mainline", "Apex (/apex)"
    if primary_path.startswith("/vendor/"):
        return "Vendor", "Vendor (/vendor)"
    if primary_path:
        return "Other", "Other"
    return "Unknown", "Unknown"


def _derive_source(category: str, installer: Optional[str]) -> str:
    if category == "User":
        if installer == "com.android.vending":
            return "Play Store"
        if installer and installer not in {"Unknown", "unset"}:
            return installer
        return "Sideload"
    if category == "Mainline":
        return "Google Mainline"
    if category == "OEM":
        return "OEM/Carrier"
    if category == "Vendor":
        return "Vendor"
    if category == "System":
        return "System"
    return category


def _normalise_installer(installer: Optional[str]) -> Optional[str]:
    if not installer or installer.lower() in {"null", "none", ""}:
        return None
    return installer
