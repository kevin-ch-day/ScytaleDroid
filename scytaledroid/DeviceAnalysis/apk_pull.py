"""apk_pull.py - Pull APK artifacts from a connected device and persist metadata."""

from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from scytaledroid.Config import app_config
from scytaledroid.Database.db_func import apk_repository as repo
from scytaledroid.DeviceAnalysis import adb_utils, inventory
from scytaledroid.DeviceAnalysis.harvest import select_package_scope
from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, text_blocks
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def pull_apks(serial: Optional[str]) -> None:
    """Pull APK files for the active device and upsert metadata into the repository."""
    if not serial:
        print(status_messages.status("No active device. Connect first to pull APKs.", level="warn"))
        menu_utils.press_enter_to_continue()
        return

    if not adb_utils.is_available():
        print(status_messages.status("adb binary not found on PATH.", level="error"))
        menu_utils.press_enter_to_continue()
        return

    snapshot = inventory.load_latest_inventory(serial)
    if not snapshot:
        print(status_messages.status("No inventory snapshot found for this device.", level="warn"))
        if menu_utils.prompt_yes_no("Run an inventory sync now?", default=True):
            inventory.run_inventory_sync(serial)
            snapshot = inventory.load_latest_inventory(serial)
        else:
            menu_utils.press_enter_to_continue()
            return

    if not snapshot or not snapshot.get("packages"):
        print(status_messages.status("Unable to retrieve inventory data after sync.", level="error"))
        menu_utils.press_enter_to_continue()
        return

    packages: List[Dict[str, object]] = snapshot.get("packages", [])  # type: ignore[assignment]
    if not packages:
        print(status_messages.status("Inventory snapshot contains no packages.", level="warn"))
        menu_utils.press_enter_to_continue()
        return

    selection, filtered_packages = select_package_scope(packages)
    if selection is None:
        print(status_messages.status("APK pull cancelled by user.", level="warn"))
        menu_utils.press_enter_to_continue()
        return
    if not filtered_packages:
        print(status_messages.status("Selection contains no packages. Nothing to pull.", level="warn"))
        menu_utils.press_enter_to_continue()
        return

    total_packages = len(filtered_packages)
    total_files = sum(len(pkg.get("apk_paths", [])) for pkg in filtered_packages)

    print()
    print(text_blocks.headline("APK Harvest", width=70))
    print(status_messages.status(
        f"Preparing to pull {total_files} APK file(s) across {total_packages} package(s)."
    ))
    print(status_messages.status(f"Scope: {selection}"))

    if not menu_utils.prompt_yes_no("Proceed with APK pull?", default=True):
        print(status_messages.status("APK pull cancelled by user.", level="warn"))
        menu_utils.press_enter_to_continue()
        return

    session_stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    dest_root = Path(app_config.DATA_DIR) / "apks" / "device_apks" / serial
    dest_root.mkdir(parents=True, exist_ok=True)

    adb_path = adb_utils.get_adb_binary()
    if not adb_path:
        print(status_messages.status("adb binary not found on PATH.", level="error"))
        menu_utils.press_enter_to_continue()
        return

    processed_packages = 0
    processed_files = 0
    stored_records = 0
    skipped_files = 0
    permission_denied: set[str] = set()
    failures: List[str] = []

    for index, package in enumerate(filtered_packages, start=1):
        package_name = str(package.get("package_name") or "").strip()
        if not package_name:
            failures.append("Encountered package without package_name; skipping entry.")
            continue

        apk_paths: Sequence[str] = sequence_from(package.get("apk_paths"))
        if not apk_paths:
            log.warning(f"No apk paths found for {package_name}; skipping.", category="device")
            continue

        print(status_messages.status(
            f"[{index}/{total_packages}] Harvesting {package_name} ({len(apk_paths)} file(s))..."
        ))

        package_dir = dest_root / package_name / session_stamp
        package_dir.mkdir(parents=True, exist_ok=True)

        slug = _slugify(str(package.get("app_label") or package_name))
        version_code = str(package.get("version_code") or "unknown")
        version_name = package.get("version_name")
        installer = package.get("installer")
        category = str(package.get("category") or "Unknown")
        is_system = category.lower() != "user"
        split_count = int(package.get("split_count") or len(apk_paths))
        group_id: Optional[int] = None
        if split_count > 1:
            try:
                group_id = repo.ensure_split_group(package_name)
            except Exception as exc:  # pragma: no cover - defensive log
                error_msg = f"Failed to ensure split group for {package_name}: {exc}"
                log.error(error_msg, category="database")
                failures.append(error_msg)
                continue

        try:
            app_id = repo.ensure_app_definition(package_name, package.get("app_label"))
        except Exception as exc:  # pragma: no cover - defensive log
            error_msg = f"Failed to ensure app definition for {package_name}: {exc}"
            log.error(error_msg, category="database")
            failures.append(error_msg)
            continue

        for file_index, source_path in enumerate(apk_paths):
            processed_files += 1
            source_path = source_path.strip()
            if not source_path:
                skipped_files += 1
                failures.append(f"Empty source path encountered for {package_name}.")
                continue

            source_name = Path(source_path).name
            base_name = f"{slug}_{version_code}__{source_name}"
            dest_path = package_dir / base_name

            pulled, reason = _ensure_local_copy(
                adb_path, serial, source_path, dest_path, package_name
            )
            if not pulled:
                skipped_files += 1
                if reason == "permission-denied":
                    permission_denied.add(package_name)
                continue

            hash_payload = _compute_hashes(dest_path)
            hashes = hash_payload["hashes"]
            file_size = hash_payload["size"]

            record = repo.ApkRecord(
                package_name=package_name,
                app_id=app_id,
                file_name=dest_path.name,
                file_size=file_size,
                is_system=is_system,
                installer=str(installer) if installer else None,
                version_name=str(version_name) if version_name else None,
                version_code=str(version_code) if version_code else None,
                md5=hashes["md5"],
                sha1=hashes["sha1"],
                sha256=hashes["sha256"],
                device_serial=serial,
                source_path=source_path,
                local_path=str(dest_path.resolve()),
                harvested_at=datetime.utcnow(),
                is_split_member=split_count > 1 and file_index > 0,
                split_group_id=group_id,
            )

            try:
                repo.upsert_apk_record(record)
                stored_records += 1
            except Exception as exc:
                error_msg = f"Failed to upsert APK metadata for {package_name} ({source_name}): {exc}"
                log.error(error_msg, category="database")
                failures.append(error_msg)

        processed_packages += 1

    _render_summary(
        processed_packages,
        processed_files,
        stored_records,
        skipped_files,
        sorted(permission_denied),
        failures,
    )
    menu_utils.press_enter_to_continue()
def _ensure_local_copy(
    adb_path: str, serial: str, source_path: str, dest_path: Path, package_name: str
) -> Tuple[bool, Optional[str]]:
    """Ensure the APK file is present locally, pulling it via adb when necessary."""
    if dest_path.exists():
        return True, None

    command = [adb_path, "-s", serial, "pull", source_path, str(dest_path)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except Exception as exc:  # pragma: no cover - defensive
        log.error(f"adb pull execution failed for {package_name}: {exc}", category="device")
        print(status_messages.status(
            f"Failed to execute adb pull for {package_name}: {exc}", level="error"
        ))
        return False, "other-error"

    if result.returncode != 0:
        stderr = result.stderr.strip()
        log.warning(
            f"adb pull returned {result.returncode} for {package_name}: {stderr}",
            category="device",
        )
        print(status_messages.status(
            f"adb pull failed for {package_name}: {stderr or 'Unknown error'}",
            level="error",
        ))
        reason = "permission-denied" if "Permission denied" in stderr else "other-error"
        return False, reason

    return True, None


def _compute_hashes(path: Path) -> Dict[str, object]:
    """Return md5/sha1/sha256 digests and file size for the provided file."""
    hashers = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for hasher in hashers.values():
                hasher.update(chunk)

    return {
        "hashes": {name: hasher.hexdigest() for name, hasher in hashers.items()},
        "size": path.stat().st_size,
    }


def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_")
    return slug or "app"


def _render_summary(
    processed_packages: int,
    processed_files: int,
    stored_records: int,
    skipped_files: int,
    permission_denied: Sequence[str],
    failures: List[str],
) -> None:
    print()
    print(text_blocks.headline("APK Harvest Summary", width=70))
    print(status_messages.status(f"Packages processed: {processed_packages}", level="info"))
    print(status_messages.status(f"Files processed: {processed_files}", level="info"))
    print(status_messages.status(f"Records upserted: {stored_records}", level="info"))
    if skipped_files:
        print(status_messages.status(f"Files skipped: {skipped_files}", level="warn"))
    if permission_denied:
        print(status_messages.status(
            "Packages skipped due to permission restrictions:", level="warn"
        ))
        for pkg in permission_denied:
            print(f"  - {pkg}")
    if failures:
        print(status_messages.status(f"Failures encountered: {len(failures)}", level="error"))
        for message in failures[:10]:
            print(f"  - {message}")
        if len(failures) > 10:
            print(f"  ... {len(failures) - 10} more")


def sequence_from(value: object) -> Sequence[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return []


__all__ = ["pull_apks"]
