"""inventory.py - Installed package scanning for connected devices."""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import re

from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import (
    error_panels,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from . import adb_utils, inventory_meta, package_profiles
from .services import device_service
from scytaledroid.DeviceAnalysis.inventory.runner import run_full_sync as _run_full_sync
from scytaledroid.DeviceAnalysis.inventory.runner import InventoryResult as RunnerInventoryResult
try:
    from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import INVENTORY_STALE_SECONDS
except Exception:  # pragma: no cover - defensive fallback
    INVENTORY_STALE_SECONDS = 1800
from scytaledroid.Database.db_core import run_sql
from scytaledroid.Database.db_func.harvest import device_inventory as inventory_repo
from scytaledroid.Database.db_func.harvest.apk_repository import ensure_app_definition


class InventorySyncAborted(RuntimeError):
    """Raised when a sync is cancelled via progress callback."""


ProgressCallback = Callable[[Dict[str, object]], bool | None]


_PROGRESS_VERBOSE = False


def set_inventory_progress_verbose(enabled: bool) -> None:
    """Enable or disable verbose progress output for this session."""

    global _PROGRESS_VERBOSE
    _PROGRESS_VERBOSE = bool(enabled)


def _emit_progress(
    callback: ProgressCallback | None, event: Dict[str, object]
) -> None:
    """Invoke *callback* with *event* and abort if it requests cancellation."""

    if not callback:
        return

    try:
        should_continue = callback(event)
    except Exception as exc:  # pragma: no cover - defensive
        raise InventorySyncAborted("Progress callback raised an exception") from exc

    if should_continue is False:
        raise InventorySyncAborted("Inventory sync cancelled by progress callback")

_STATE_ROOT = Path(app_config.DATA_DIR) / app_config.DEVICE_STATE_DIR

_CATEGORY_ORDER = {
    "User": 0,
    "OEM": 1,
    "System": 2,
    "Mainline": 3,
    "Vendor": 4,
    "Other": 5,
    "Unknown": 6,
}

_PARTITION_ORDER = [
    "Data (/data)",
    "Product (/product)",
    "System (/system, /system_ext)",
    "Apex (/apex)",
    "Vendor (/vendor)",
    "Other",
    "Unknown",
]


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


def _normalise_hash_token(*values: object) -> str:
    parts = []
    for value in values:
        if value is None:
            parts.append("")
        else:
            parts.append(str(value))
    return "|".join(parts)


def _hash_rows(rows: Iterable[Dict[str, object]]) -> str:
    digest = hashlib.sha256()
    tokens = []
    for row in rows:
        tokens.append(
            _normalise_hash_token(
                row.get("package_name"),
                row.get("version_name"),
                row.get("version_code"),
                row.get("primary_path"),
            )
        )
    for token in sorted(tokens):
        digest.update(token.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _load_canonical_metadata(package_names: Iterable[str]) -> Dict[str, Dict[str, object]]:
    """Fetch canonical definitions keyed by package name."""

    normalised = sorted({str(name).lower() for name in package_names if name})
    if not normalised:
        return {}

    placeholders = ", ".join(["%s"] * len(normalised))

    def _build_query(include_profiles: bool) -> str:
        profile_select = (
            "            d.profile_id,\n            d.profile_name"
            if include_profiles
            else "            NULL AS profile_id,\n            NULL AS profile_name"
        )
        return f"""
            SELECT
                LOWER(d.package_name) AS package_key,
                d.app_name,
                d.category_id,
                c.category_name,
                {profile_select}
            FROM android_app_definitions d
            LEFT JOIN android_app_categories c ON c.category_id = d.category_id
            WHERE LOWER(d.package_name) IN ({placeholders})
        """

    rows: List[Dict[str, object]]
    query = _build_query(include_profiles=True)
    try:
        rows = run_sql(query, tuple(normalised), fetch="all", dictionary=True) or []
    except RuntimeError as exc:
        if "Unknown column 'd.profile_id'" not in str(exc):
            raise
        log.warning(
            "Profiles unsupported by current android_app_definitions schema; continuing without profile metadata.",
            category="inventory",
        )
        fallback_query = _build_query(include_profiles=False)
        rows = run_sql(fallback_query, tuple(normalised), fetch="all", dictionary=True) or []
    canonical: Dict[str, Dict[str, object]] = {}
    for row in rows:
        key = str(row.get("package_key") or "").lower()
        if not key:
            continue
        canonical[key] = {
            "app_name": row.get("app_name"),
            "category_id": row.get("category_id"),
            "category_name": row.get("category_name"),
            "profile_id": row.get("profile_id"),
            "profile_name": row.get("profile_name"),
        }
    return canonical


def run_inventory_sync(
    serial: Optional[str],
    *,
    filter_name: Optional[str] = None,
    filter_fn: Optional[Callable[[Dict[str, object]], bool]] = None,
    interactive: bool = True,
    progress_callback: ProgressCallback | None = None,
    expected_total_seconds: Optional[float] = None,
) -> None:
    """Scan the device, sync package definitions, and display results."""
    if not serial:
        error_panels.print_error_panel(
            "Inventory",
            "No active device. Connect first to scan.",
            hint="Use the device selector before running inventory.",
        )
        prompt_utils.press_enter_to_continue()
        return

    previous_meta = inventory_meta.load_latest(serial) if serial else None
    previous_snapshot = load_latest_inventory(serial) if serial else None
    previous_packages: set[str] | None = None
    previous_split_packages: Optional[int] = None
    had_previous_snapshot = previous_snapshot is not None
    if previous_snapshot:
        packages_payload = previous_snapshot.get("packages")
        if isinstance(packages_payload, list):
            extracted: set[str] = set()
            split_counter = 0
            for item in packages_payload:
                if isinstance(item, dict):
                    name = item.get("package_name")
                    if isinstance(name, str) and name:
                        extracted.add(name)
                    if _split_count(item) > 1:
                        split_counter += 1
            previous_packages = extracted
            previous_split_packages = split_counter

    if interactive:
        print()
        print(text_blocks.headline("Inventory & database sync", width=70))
        print(status_messages.status("Collecting installed packages..."))
    run_start = time.time()

    adb_utils.clear_package_caches(serial)
    packages_with_versions = adb_utils.list_packages_with_versions(serial)
    if not packages_with_versions:
        error_panels.print_error_panel(
            "Inventory",
            "adb did not return any packages.",
            hint="Check that the device is unlocked and adb has permissions.",
        )
        prompt_utils.press_enter_to_continue()
        return

    package_names = [entry[0] for entry in packages_with_versions if entry[0]]
    total = len(package_names)

    current_name_hash = inventory_meta.compute_name_hash(package_names)
    current_signature_hash = inventory_meta.compute_signature_hash(packages_with_versions)

    if (
        filter_fn is None
        and previous_meta
        and current_signature_hash
        and previous_meta.package_signature_hash
        and current_signature_hash == previous_meta.package_signature_hash
    ):
        _emit_progress(
            progress_callback,
            {
                "phase": "start",
                "total": total,
                "estimated_total_seconds": expected_total_seconds,
            },
        )
        _emit_progress(
            progress_callback,
            {
                "phase": "complete",
                "total": total,
                "elapsed_seconds": 0.0,
            },
        )
        if interactive:
            print()
            print(
                status_messages.status(
                    "Inventory unchanged; package signature matches the previous snapshot.",
                    level="info",
                )
            )
            prompt_utils.press_enter_to_continue()
        return

    _emit_progress(
        progress_callback,
        {
            "phase": "start",
            "total": total,
            "estimated_total_seconds": expected_total_seconds,
        },
    )

    device_properties = adb_utils.get_basic_properties(serial)
    fingerprint = device_properties.get("build_fingerprint") if device_properties else None

    canonical_metadata = _load_canonical_metadata(package_names)

    metadata_rows: List[Dict[str, object]] = []
    package_definitions: Dict[str, Optional[str]] = {}
    entries_by_package: Dict[str, Dict[str, object]] = {}
    progress_interval = max(20, total // 20 or 1)
    scan_start = time.time()
    progress_line_length = 0
    progress_line_visible = False
    split_processed = 0
    for index, package_name in enumerate(package_names, start=1):
        paths = adb_utils.get_package_paths(serial, package_name)
        metadata = adb_utils.get_package_metadata(serial, package_name)
        package_key = package_name.lower()
        canonical_entry = canonical_metadata.get(package_key)
        entry = _compose_inventory_entry(package_name, paths, metadata, canonical_entry)
        metadata_rows.append(entry)
        normalized_package = entry.get("package_name") or package_name
        normalized_key = str(normalized_package).lower()
        app_label = entry.get("app_label")
        package_definitions.setdefault(normalized_key, app_label if isinstance(app_label, str) else None)
        entries_by_package[normalized_key] = entry

        if _split_count(entry) > 1:
            split_processed += 1

        if interactive and _PROGRESS_VERBOSE:
            percentage = (index / total) * 100
            print(
                status_messages.status(
                    f"Processed {index}/{total} packages ({percentage:.1f}%).",
                    level="info",
                )
            )

        if index % progress_interval == 0 or index == total:
            elapsed = time.time() - scan_start
            estimated_total = None
            if index:
                estimated_total = (elapsed / index) * total if elapsed else expected_total_seconds
            eta = (estimated_total - elapsed) if estimated_total and estimated_total > elapsed else None
            _emit_progress(
                progress_callback,
                {
                    "phase": "progress",
                    "processed": index,
                    "total": total,
                    "percentage": (index / total) * 100,
                    "elapsed_seconds": elapsed,
                    "eta_seconds": eta,
                    "estimated_total_seconds": estimated_total or expected_total_seconds,
                },
            )

            if interactive and not _PROGRESS_VERBOSE:
                progress_line = _format_progress_line(
                    processed=index,
                    total=total,
                    elapsed_seconds=elapsed,
                    eta_seconds=eta,
                    split_processed=split_processed,
                )
                visible_length = _visible_length(progress_line)
                padding = " " * max(0, progress_line_length - visible_length)
                print(f"\r{progress_line}{padding}", end="", flush=True)
                progress_line_length = visible_length
                progress_line_visible = True

    if interactive and progress_line_visible:
        print()

    package_hash = _hash_rows(metadata_rows)
    package_list_hash = current_name_hash or inventory_meta.compute_name_hash(package_names)
    package_signature_hash = inventory_meta.compute_signature_hash(
        inventory_meta.snapshot_signatures(metadata_rows)
    )
    total_elapsed = time.time() - run_start
    snapshot_path = _persist_inventory(
        serial,
        metadata_rows,
        package_hash=package_hash,
        package_list_hash=package_list_hash,
        package_signature_hash=package_signature_hash,
        build_fingerprint=fingerprint,
        duration_seconds=total_elapsed,
        snapshot_type="full",
    )

    _emit_progress(
        progress_callback,
        {
            "phase": "complete",
            "total": total,
            "elapsed_seconds": total_elapsed,
        },
    )

    split_packages = split_processed
    current_package_names: set[str] = set()
    for entry in metadata_rows:
        package_value = entry.get("package_name")
        if isinstance(package_value, str) and package_value:
            current_package_names.add(package_value)
    new_packages = None
    removed_packages = None
    if had_previous_snapshot:
        previous_set = previous_packages or set()
        new_packages = len(current_package_names - previous_set)
        removed_packages = len(previous_set - current_package_names)

    if interactive:
        _print_sync_summary(
            snapshot_path,
            total_packages=len(metadata_rows),
            split_packages=split_packages,
            elapsed_seconds=total_elapsed,
            previous_total=previous_meta.package_count if previous_meta else None,
            previous_split=previous_split_packages,
            new_packages=new_packages,
            removed_packages=removed_packages,
        )

    synced = 0
    for pkg, name in package_definitions.items():
        entry = entries_by_package.get(pkg)
        inferred_category = bool(entry.get("inferred_category")) if entry else False
        inferred_profile = bool(entry.get("inferred_profile")) if entry else False

        if (
            previous_packages is not None
            and pkg in previous_packages
            and entry
            and not entry.get("review_needed")
            and not inferred_category
            and not inferred_profile
        ):
            continue

        category_name = _get_canonical_category(entry) if entry else None
        profile_id = entry.get("profile_id") if entry else None
        profile_name = entry.get("profile_name") if entry else None
        try:
            ensure_app_definition(
                pkg,
                name,
                category_name=category_name if inferred_category else None,
                profile_id=str(profile_id) if inferred_profile and profile_id else None,
                profile_name=profile_name if inferred_profile and profile_name else None,
            )
            synced += 1
        except Exception as exc:  # pragma: no cover - defensive logging
            print(status_messages.status(f"Failed to register {pkg}: {exc}", level="warn"))

    if synced and interactive:
        print(status_messages.status(f"Synced {synced} package definitions to database.", level="info"))

    if interactive:
        _render_inventory_summary(metadata_rows)
    else:
        base_message = f"Inventory captured: {len(metadata_rows)} packages"
        if snapshot_path:
            base_message += f" (saved to {snapshot_path})"
        status_messages.print_status(base_message, level="info")

    # Streamlined flow: do not prompt for subsets or next steps here.


def inventory_sync_menu(serial: Optional[str]) -> None:
    if not serial:
        error_panels.print_error_panel(
            "Inventory",
            "No active device connected.",
            hint="Select a device from the Device Analysis dashboard first.",
        )
        prompt_utils.press_enter_to_continue()
        return

    while True:
        print()
        menu_utils.print_header("Inventory & Sync")
        status = device_service.fetch_inventory_metadata(serial)
        if status and status.last_run_ts:
            freshness = f"{status.status_label} ({status.age_display})"
            if status.is_stale:
                print(status_messages.status(f"Current inventory: {freshness}", level="warn"))
                print(
                    status_messages.status(
                        "Recommendation: run a full sync to refresh packages and DB entries.",
                        level="info",
                    )
                )
            else:
                print(status_messages.status(f"Current inventory: {freshness}", level="info"))
        threshold_label = f"{INVENTORY_STALE_SECONDS // 3600}h" if INVENTORY_STALE_SECONDS >= 3600 else f"{INVENTORY_STALE_SECONDS // 60}m"
        print(f"Staleness threshold: {threshold_label}")
        options = {
            "1": "Sync all packages",
            "2": "Sync user-installed apps",
            "3": "Sync system/OEM modules",
            "4": "Sync social & messaging apps",
            "5": "Sync finance & shopping apps",
            "6": "Verify database app definitions",
        }
        menu_utils.print_menu(options, is_main=False)
        choice = prompt_utils.get_choice(list(options.keys()) + ["0"])

        if choice == "0":
            break
        if choice == "1":
            device_service.sync_inventory(serial)
            return
        elif choice == "2":
            device_service.sync_inventory(
                serial,
                filter_name="User-installed apps",
                filter_fn=lambda entry: (
                    (_get_canonical_category(entry) or "Unknown") == "User"
                ),
            )
            return
        elif choice == "3":
            device_service.sync_inventory(
                serial,
                filter_name="System & OEM modules",
                filter_fn=lambda entry: (
                    (_get_canonical_category(entry) or "Unknown")
                    in {"System", "OEM", "Mainline", "Vendor"}
                ),
            )
            return
        elif choice == "4":
            profiles = {"Social", "Messaging"}
            device_service.sync_inventory(
                serial,
                filter_name="Social & Messaging apps",
                filter_fn=lambda entry: str(entry.get("profile_name")) in profiles,
            )
            return
        elif choice == "5":
            profiles = {"Finance", "Shopping"}
            device_service.sync_inventory(
                serial,
                filter_name="Finance & Shopping apps",
                filter_fn=lambda entry: str(entry.get("profile_name")) in profiles,
            )
            return
        elif choice == "6":
            _verify_app_definitions()
        else:
            print(status_messages.status("Selection not available yet.", level="warn"))
            prompt_utils.press_enter_to_continue()



def run_device_summary(serial: Optional[str]) -> None:
    """Display the latest inventory snapshot with highlighted insights."""
    if not serial:
        error_panels.print_error_panel(
            "Inventory Summary",
            "No active device. Connect first to show summary.",
        )
        prompt_utils.press_enter_to_continue()
        return

    snapshot = load_latest_inventory(serial)
    if not snapshot:
        error_panels.print_error_panel(
            "Inventory Summary",
            "No inventory snapshot found for this device.",
            hint="Run a new inventory sync to capture the current state.",
        )
        if prompt_utils.prompt_yes_no("Run a new inventory sync now?", default=True):
            run_inventory_sync(serial)
        return

    packages: List[Dict[str, object]] = snapshot.get("packages", [])  # type: ignore[assignment]
    generated_at = snapshot.get("generated_at")

    print()
    print(text_blocks.headline("Device inventory overview", width=70))
    if generated_at:
        status_messages.print_status(f"Snapshot captured {generated_at}")

    if not packages:
        print(status_messages.status("Snapshot contains no package entries.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    _render_inventory_summary(packages)

    print()
    print(text_blocks.headline("User applications (preview)", width=70))
    user_preview = _preview_packages(packages, category="User", limit=12)
    if user_preview:
        table_utils.render_table(["Package", "App", "Version", "Profile", "Split", "Path"], user_preview)
    else:
        print(status_messages.status("No user applications detected in snapshot.", level="info"))

    system_preview = _preview_packages(packages, category="System", limit=8)
    if system_preview:
        print()
        print(text_blocks.headline("System components (preview)", width=70))
        table_utils.render_table(["Package", "Component", "Version", "Profile", "Split", "Path"], system_preview)

        prompt_utils.press_enter_to_continue()


def sync_subset(
    packages: Sequence[object],
    *,
    serial: str,
    progress_callback: ProgressCallback | None = None,
) -> Optional[Path]:
    """Capture a scoped inventory snapshot for ``packages`` only."""

    if not serial:
        raise ValueError("serial is required for sync_subset")

    normalized: List[str] = []
    seen: set[str] = set()
    for entry in packages:
        package_name: Optional[str]
        if isinstance(entry, str):
            package_name = entry.strip()
        elif isinstance(entry, dict):
            raw_name = entry.get("package_name")
            package_name = raw_name.strip() if isinstance(raw_name, str) else None
        else:
            raw_name = getattr(entry, "package_name", None)
            package_name = raw_name.strip() if isinstance(raw_name, str) else None

        if not package_name:
            continue
        if package_name in seen:
            continue
        normalized.append(package_name)
        seen.add(package_name)

    if not normalized:
        return None

    total = len(normalized)
    _emit_progress(
        progress_callback,
        {"phase": "start", "total": total},
    )

    device_properties = adb_utils.get_basic_properties(serial)
    fingerprint = device_properties.get("build_fingerprint") if device_properties else None

    canonical_metadata = _load_canonical_metadata(normalized)

    metadata_rows: List[Dict[str, object]] = []
    progress_interval = max(1, total // 10 or 1)
    scan_start = time.time()
    split_processed = 0

    for index, package_name in enumerate(normalized, start=1):
        paths = adb_utils.get_package_paths(serial, package_name)
        metadata = adb_utils.get_package_metadata(serial, package_name)
        package_key = package_name.lower()
        canonical_entry = canonical_metadata.get(package_key)
        entry = _compose_inventory_entry(package_name, paths, metadata, canonical_entry)
        metadata_rows.append(entry)

        if _split_count(entry) > 1:
            split_processed += 1

        if index % progress_interval == 0 or index == total:
            elapsed = time.time() - scan_start
            estimated_total = (elapsed / index) * total if index else None
            eta = (estimated_total - elapsed) if estimated_total and estimated_total > elapsed else None
            _emit_progress(
                progress_callback,
                {
                    "phase": "progress",
                    "processed": index,
                    "total": total,
                    "percentage": (index / total) * 100,
                    "elapsed_seconds": elapsed,
                    "eta_seconds": eta,
                    "estimated_total_seconds": estimated_total,
                    "split_processed": split_processed,
                },
            )

    run_elapsed = time.time() - scan_start

    package_hash = _hash_rows(metadata_rows)
    package_list_hash = inventory_meta.compute_name_hash(normalized)
    package_signature_hash = inventory_meta.compute_signature_hash(
        inventory_meta.snapshot_signatures(metadata_rows)
    )
    scope_hash = inventory_meta.compute_scope_hash(metadata_rows)

    snapshot_path = _persist_inventory(
        serial,
        metadata_rows,
        package_hash=package_hash,
        package_list_hash=package_list_hash,
        package_signature_hash=package_signature_hash,
        build_fingerprint=fingerprint,
        duration_seconds=run_elapsed,
        snapshot_type="subset",
        scope_hash=scope_hash,
        filename_suffix="subset",
    )

    _emit_progress(
        progress_callback,
        {
            "phase": "complete",
            "total": total,
            "elapsed_seconds": run_elapsed,
            "scope_hash": scope_hash,
        },
    )

    return snapshot_path


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


def _get_canonical_category(entry: Dict[str, object]) -> Optional[str]:
    value = entry.get("category_name") or entry.get("category")
    if value is None or value == "":
        return None
    return str(value)


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


def _persist_inventory(
    serial: str,
    rows: List[Dict[str, object]],
    *,
    package_hash: Optional[str] = None,
    package_list_hash: Optional[str] = None,
    package_signature_hash: Optional[str] = None,
    build_fingerprint: Optional[str] = None,
    duration_seconds: Optional[float] = None,
    snapshot_type: str = "full",
    scope_hash: Optional[str] = None,
    filename_suffix: Optional[str] = None,
) -> Path:
    from scytaledroid.DeviceAnalysis.inventory.snapshot_io import persist_snapshot

    return persist_snapshot(
        serial=serial,
        rows=rows,
        package_hash=package_hash,
        package_list_hash=package_list_hash,
        package_signature_hash=package_signature_hash,
        build_fingerprint=build_fingerprint,
        duration_seconds=duration_seconds,
        snapshot_type=snapshot_type,
        scope_hash=scope_hash,
        filename_suffix=filename_suffix,
    )


def _format_duration(seconds: Optional[float]) -> str:
    if seconds is None or seconds < 0:
        return "--:--"

    total_seconds = int(round(seconds))
    minutes, secs = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _format_delta_text(current: int, previous: Optional[int]) -> str:
    if previous is None:
        return "(first snapshot)"

    delta = current - previous
    if delta == 0:
        return "(no change vs last snapshot)"

    sign = "+" if delta > 0 else "-"
    return f"(Δ {sign}{abs(delta)} vs last snapshot)"


def _format_progress_line(
    *,
    processed: int,
    total: int,
    elapsed_seconds: float,
    eta_seconds: Optional[float],
    split_processed: int,
) -> str:
    percentage = (processed / total) * 100 if total else 0.0
    eta_text = _format_duration(eta_seconds)
    elapsed_text = _format_duration(elapsed_seconds)
    message = (
        f"Processed {processed}/{total} packages ({percentage:.1f}%) "
        f"• ETA {eta_text} • Elapsed {elapsed_text} • Split APKs {split_processed}"
    )
    return status_messages.status(message, show_icon=False)


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _visible_length(text: str) -> int:
    return len(_ANSI_ESCAPE_RE.sub("", text))


def _print_sync_summary(
    snapshot_path: Path,
    *,
    total_packages: int,
    split_packages: int,
    elapsed_seconds: float,
    previous_total: Optional[int],
    previous_split: Optional[int],
    new_packages: Optional[int],
    removed_packages: Optional[int],
) -> None:
    summary_lines = [
        status_messages.status("Inventory sync complete", level="success"),
        status_messages.status(
            f"Snapshot saved to {snapshot_path}",
            show_icon=False,
        ),
        status_messages.status(
            f"Packages captured: {total_packages} {_format_delta_text(total_packages, previous_total)}",
            show_icon=False,
        ),
        status_messages.status(
            f"Split APKs: {split_packages} {_format_delta_text(split_packages, previous_split)}",
            show_icon=False,
        ),
    ]

    if new_packages is not None and removed_packages is not None:
        summary_lines.append(
            status_messages.status(
                f"New packages: {new_packages} • Removed: {removed_packages}",
                show_icon=False,
            )
        )

    summary_lines.append(
        status_messages.status(
            f"Scan duration: {_format_duration(elapsed_seconds)}",
            show_icon=False,
        )
    )

    print()
    print(text_blocks.boxed(summary_lines, width=70))


def _render_inventory_table(rows: List[Dict[str, object]]) -> None:
    """Render a compact, readable list of inventory entries."""
    if not rows:
        print("No inventory data available.")
        return

    sorted_rows = sorted(
        rows,
        key=lambda entry: (
            _CATEGORY_ORDER.get(_get_canonical_category(entry) or "Unknown", 99),
            str(entry.get("app_label") or entry.get("package_name") or "").lower(),
        ),
    )

    max_preview = 25
    preview_rows = sorted_rows[:max_preview]
    width = 70

    for index, entry in enumerate(preview_rows, start=1):
        package_name = str(entry.get("package_name") or "?")
        label = str(entry.get("app_label") or package_name)
        version = str(entry.get("version_name") or entry.get("version_code") or "?")
        category = _get_canonical_category(entry) or "Unknown"
        source = str(entry.get("source") or category)
        profile_name = str(entry.get("profile_name") or "-")
        split_count = _split_count(entry)
        split_display = "No" if split_count <= 1 else f"Yes ({split_count})"
        primary_path = str(entry.get("primary_path") or "?")

        header = f"{index:>3}. {package_name}"
        print(header)
        meta_line = f"     {label}  |  Version: {version}  |  Source: {source}  |  Profile: {profile_name}  |  Split APK: {split_display}"
        print(textwrap.fill(meta_line, width=width, subsequent_indent="     "))
        print(textwrap.fill(f"     Path: {primary_path}", width=width, subsequent_indent="           "))
        print()

    if len(sorted_rows) > max_preview:
        remaining = len(sorted_rows) - max_preview
        print(status_messages.status(f"+ {remaining} more entries saved to report.", level="info"))


def load_latest_inventory(serial: str) -> Optional[Dict[str, object]]:
    """Return the most recently persisted inventory snapshot if available."""
    latest_file = _STATE_ROOT / serial / "inventory" / "latest.json"
    if not latest_file.exists():
        return None

    try:
        return json.loads(latest_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning(
            f"Failed to parse {latest_file.relative_to(Path.cwd())}",
            category="device",
        )
        return None


def _render_inventory_summary(rows: List[Dict[str, object]]) -> None:
    total = len(rows)
    category_counts = Counter(
        (_get_canonical_category(entry) or "Unknown")
        for entry in rows
    )
    source_counts = Counter(str(entry.get("source") or "Unknown") for entry in rows)
    split_packages = sum(1 for entry in rows if _split_count(entry) > 1)
    profile_counts = Counter(str(entry.get("profile_name") or "Unclassified") for entry in rows)

    print()
    print(text_blocks.headline("Inventory summary", width=70))
    summary_rows: List[List[str]] = [
        ["Total packages", str(total)],
        ["User apps (/data)", str(category_counts.get("User", 0))],
        ["OEM overlays (/product)", str(category_counts.get("OEM", 0))],
        ["System core (/system*)", str(category_counts.get("System", 0))],
        ["Google mainline (/apex)", str(category_counts.get("Mainline", 0))],
        ["Vendor partitions", str(category_counts.get("Vendor", 0))],
        ["Split APK packages", str(split_packages)],
        ["Play Store installs", str(source_counts.get("Play Store", 0))],
        ["Sideload / unknown", str(source_counts.get("Sideload", 0))],
    ]

    for label, value in _partition_breakdown(rows):
        summary_rows.append([label, value])

    review_flags = sum(1 for entry in rows if entry.get("review_needed"))
    if review_flags:
        summary_rows.append(["Needs review", str(review_flags)])

    table_utils.render_table(["Metric", "Count"], summary_rows)

    notable_profiles = [
        (name, count)
        for name, count in profile_counts.items()
        if name != "Unclassified" and count > 0
    ]
    if notable_profiles:
        print()
        print(text_blocks.headline("Category matches", width=70))
        category_rows = [
            [name, str(count)]
            for name, count in sorted(notable_profiles, key=lambda item: (-item[1], item[0]))
        ]
        table_utils.render_table(["Profile", "Packages"], category_rows)


def _partition_breakdown(rows: List[Dict[str, object]]) -> List[tuple[str, str]]:
    counts = Counter(str(entry.get("partition") or "Other") for entry in rows)
    ordered: List[tuple[str, str]] = []
    for label in _PARTITION_ORDER:
        value = counts.get(label, 0)
        if value:
            ordered.append((label, str(value)))
    for label, value in counts.items():
        if label not in _PARTITION_ORDER and value:
            ordered.append((label, str(value)))
    return ordered


def _preview_packages(
    packages: List[Dict[str, object]],
    *,
    category: str,
    limit: int,
) -> List[List[str]]:
    filtered = []
    for pkg in packages:
        category_value = _get_canonical_category(pkg) or "User"
        if category_value == category:
            filtered.append(pkg)

    def sort_key(pkg: Dict[str, object]) -> str:
        return str(pkg.get("app_label") or pkg.get("package_name") or "").lower()

    filtered.sort(key=sort_key)
    preview_rows: List[List[str]] = []
    for pkg in filtered[:limit]:
        package_name = str(pkg.get("package_name") or "?")
        app_label = str(pkg.get("app_label") or package_name)
        version = str(pkg.get("version_name") or pkg.get("version_code") or "?")
        split_flag = "Yes" if _split_count(pkg) > 1 else "No"
        paths = pkg.get("apk_paths")
        if isinstance(paths, list) and paths:
            path = str(paths[0])
        else:
            path = str(pkg.get("primary_path") or "?")
        profile_name = str(pkg.get("profile_name") or "-")
        preview_rows.append([package_name, app_label, version, profile_name, split_flag, path])

    return preview_rows


def _inventory_selection_menu(rows: List[Dict[str, object]]) -> None:
    if not rows:
        print(status_messages.status("No inventory results available.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    grouped = _group_packages_by_profile(rows)
    profile_items = sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0].lower()))
    profile_names = [name for name, _ in profile_items]

    while True:
        print()
        print(text_blocks.headline("Inventory subsets", width=70))
        option_labels: Dict[str, str] = {}
        for index, name in enumerate(profile_names, start=1):
            option_labels[str(index)] = f"{name} ({len(grouped[name])})"
        option_labels["A"] = f"Show all packages ({len(rows)})"
        menu_utils.print_menu(option_labels, is_main=False)
        choice = prompt_utils.get_choice(list(option_labels.keys()) + ["0"])

        if choice == "0":
            break

        normalized_choice = choice.upper()
        if normalized_choice == "A":
            _render_inventory_table(rows)
            prompt_utils.press_enter_to_continue()
            continue

        try:
            selected_index = int(choice) - 1
            if selected_index < 0 or selected_index >= len(profile_names):
                raise ValueError
        except ValueError:
            print(status_messages.status("Invalid selection.", level="warn"))
            continue

        selected_profile = profile_names[selected_index]
        _render_inventory_table(grouped[selected_profile])
        prompt_utils.press_enter_to_continue()


def _group_packages_by_profile(rows: List[Dict[str, object]]) -> Dict[str, List[Dict[str, object]]]:
    grouped: Dict[str, List[Dict[str, object]]] = {}
    for entry in rows:
        profile = entry.get("profile_name")
        if not profile or str(profile).strip() in {"", "-"}:
            profile_key = "Unclassified"
        else:
            profile_key = str(profile)
        grouped.setdefault(profile_key, []).append(entry)
    return grouped


def _verify_app_definitions() -> None:
    print()
    menu_utils.print_header("Android App Definitions")

    missing_defs = run_sql(
        """
        SELECT DISTINCT LOWER(r.package_name) AS package_name
        FROM android_apk_repository r
        LEFT JOIN android_app_definitions d ON LOWER(r.package_name) = d.package_name
        WHERE d.app_id IS NULL
        ORDER BY package_name
        """,
        fetch="all",
        dictionary=True,
    ) or []

    null_names = run_sql(
        """
        SELECT package_name
        FROM android_app_definitions
        WHERE app_name IS NULL OR app_name = ''
        ORDER BY package_name
        """,
        fetch="all",
        dictionary=True,
    ) or []

    orphan_defs = run_sql(
        """
        SELECT d.package_name
        FROM android_app_definitions d
        LEFT JOIN android_apk_repository r ON d.package_name = LOWER(r.package_name)
        WHERE r.apk_id IS NULL
        ORDER BY d.package_name
        """,
        fetch="all",
        dictionary=True,
    ) or []

    print(status_messages.status(f"Definitions missing for repository packages: {len(missing_defs)}", level="info"))
    _print_samples(missing_defs)

    print(status_messages.status(f"Definitions lacking friendly app name: {len(null_names)}", level="info"))
    _print_samples(null_names)

    print(status_messages.status(f"Definitions without repository APKs: {len(orphan_defs)}", level="info"))
    _print_samples(orphan_defs)

    print(status_messages.status("Returning to inventory menu...", level="info"))


def _print_samples(rows: List[Dict[str, object]], limit: int = 10) -> None:
    if not rows:
        print("  (none)")
        return
    for row in rows[:limit]:
        package = row.get("package_name") or row.get("PACKAGE_NAME")
        print(f"  - {package}")
    if len(rows) > limit:
        print(f"  ... {len(rows) - limit} more")
