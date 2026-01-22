"""Shared helpers for APK harvest implementations."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Mapping, MutableMapping, Optional, Tuple

from scytaledroid.Config import app_config
import os
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .models import ArtifactError, InventoryRow

DEFAULT_META_FIELDS: Tuple[str, ...] = (
    "package_name",
    "app_label",
    "installer",
    "version_name",
    "version_code",
    "file_name",
    "file_size",
    "source_path",
    "local_path",
    "sha256",
    "sha1",
    "md5",
    "captured_at",
    "session_stamp",
    "device_serial",
    "pull_mode",
    "is_split_member",
    "split_group_id",
    "apk_id",
    "occurrence_index",
    "category",
    "artifact",
)


def _harvest_base_dir() -> Path:
    """Return the absolute base directory for harvested APKs."""

    return (Path(app_config.DATA_DIR) / "apks").resolve()


def normalise_local_path(dest_path: Path) -> str:
    """Return the harvest-relative path for *dest_path*."""

    try:
        base = _harvest_base_dir()
        relative = dest_path.resolve().relative_to(base)
        return relative.as_posix()
    except ValueError:
        # Fallback to POSIX string when the file is outside the expected tree
        return dest_path.as_posix()


def resolve_storage_root() -> tuple[str, str]:
    """Return (host_name, data_root) used for storage root registration."""

    host = socket.gethostname()
    data_root = _harvest_base_dir().as_posix()
    return host, data_root


@dataclass(frozen=True)
class HarvestOptions:
    """Resolved configuration values that control harvest behaviour."""

    dedupe_sha256: bool = True
    keep_last: int = 1
    write_db: bool = True
    write_meta: bool = True
    meta_fields: Tuple[str, ...] = DEFAULT_META_FIELDS
    # Default stays "legacy" for compatibility with older menu paths; new
    # call sites should pass an explicit mode (e.g., "quick", "full", "test").
    pull_mode: str = "legacy"


def load_options(config: object, *, pull_mode: str) -> HarvestOptions:
    """Coerce configuration attributes into :class:`HarvestOptions`."""

    dedupe = bool(getattr(config, "HARVEST_DEDUP_SHA256", True))
    keep_last_raw = getattr(config, "HARVEST_KEEP_LAST", 1)
    try:
        keep_last = int(keep_last_raw)
    except (TypeError, ValueError):
        keep_last = 1
    if keep_last < 1:
        keep_last = 1

    write_db = bool(getattr(config, "HARVEST_WRITE_DB", True))
    write_meta = bool(getattr(config, "HARVEST_WRITE_META", True))

    meta_fields_raw = getattr(config, "HARVEST_META_FIELDS", DEFAULT_META_FIELDS)
    if isinstance(meta_fields_raw, str):
        candidates = [part.strip() for part in meta_fields_raw.split(",")]
    elif isinstance(meta_fields_raw, (list, tuple)):
        candidates = [str(field).strip() for field in meta_fields_raw]
    else:
        candidates = []

    if candidates:
        fields: Tuple[str, ...] = tuple(field for field in candidates if field)
        meta_fields = fields or DEFAULT_META_FIELDS
    else:
        meta_fields = DEFAULT_META_FIELDS

    return HarvestOptions(
        dedupe_sha256=dedupe,
        keep_last=keep_last,
        write_db=write_db,
        write_meta=write_meta,
        meta_fields=meta_fields,
        pull_mode=pull_mode,
    )


@dataclass
class DedupeTracker:
    """Track sha256 collisions and determine whether to keep artifacts."""

    options: HarvestOptions
    counts: MutableMapping[str, int] = field(default_factory=dict)
    skipped: int = 0

    def register(self, sha256: str) -> Tuple[bool, int]:
        """Record *sha256* and return (keep, occurrence_index)."""

        current = self.counts.get(sha256, 0) + 1
        self.counts[sha256] = current
        if not self.options.dedupe_sha256:
            return True, current
        if current <= self.options.keep_last:
            return True, current
        self.skipped += 1
        return False, current


def compute_hashes(dest_path: Path) -> Dict[str, str]:
    """Return md5/sha1/sha256 digests for *dest_path*."""

    hashers = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }
    with dest_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def write_metadata_sidecar(
    dest_path: Path,
    *,
    inventory: Mapping[str, object],
    artifact: Mapping[str, object],
    hashes: Mapping[str, str],
    serial: str,
    session_stamp: str,
    options: HarvestOptions,
    extra: Optional[Mapping[str, object]] = None,
) -> Optional[Path]:
    """Write a ``*.meta.json`` sidecar next to *dest_path* when enabled."""

    if not options.write_meta:
        return None

    captured_at = datetime.now(timezone.utc).isoformat()
    payload: Dict[str, object] = {
        "package_name": inventory.get("package_name"),
        "app_label": inventory.get("app_label"),
        "installer": inventory.get("installer"),
        "version_name": inventory.get("version_name"),
        "version_code": inventory.get("version_code"),
        "file_name": dest_path.name,
        "file_size": dest_path.stat().st_size if dest_path.exists() else None,
        "source_path": artifact.get("source_path"),
        "local_path": normalise_local_path(dest_path),
        "sha256": hashes.get("sha256"),
        "sha1": hashes.get("sha1"),
        "md5": hashes.get("md5"),
        "captured_at": captured_at,
        "session_stamp": session_stamp,
        "device_serial": serial,
        "pull_mode": options.pull_mode,
        "is_split_member": artifact.get("is_split_member"),
        "split_group_id": artifact.get("split_group_id"),
    }
    if extra:
        payload.update(extra)

    filtered = {key: payload.get(key) for key in options.meta_fields if key in payload}
    meta_path = dest_path.with_suffix(dest_path.suffix + ".meta.json")
    meta_path.write_text(json.dumps(filtered, indent=2, sort_keys=True), encoding="utf-8")
    return meta_path


def adb_pull(
    *,
    adb_path: str,
    serial: str,
    source_path: str,
    dest_path: Path,
    package_name: str,
    verbose: bool,
):
    """Ensure *dest_path* exists locally by issuing ``adb pull``."""

    if dest_path.exists():
        return True

    command = [adb_path, "-s", serial, "pull", source_path, str(dest_path)]
    if verbose:
        print(status_messages.status(f"Executing: {' '.join(command)}", level="info"))
    try:
        completed = subprocess.run(
            command,
            capture_output=not verbose,
            text=True,
            check=False,
        )
    except Exception as exc:  # pragma: no cover - defensive
        log.error(f"adb pull execution failed for {package_name}: {exc}", category="device")
        return ArtifactError(source_path=source_path, reason=str(exc))

    if completed.returncode != 0:
        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        stderr = stderr or stdout or "adb pull failed"
        log.warning(
            f"adb pull returned {completed.returncode} for {package_name}: {stderr}",
            category="device",
        )
        level = "warn" if "permission denied" in stderr.lower() else "error"
        print(status_messages.status(f"adb pull failed: {stderr}", level=level))
        reason = "permission denied" if "permission denied" in stderr.lower() else stderr
        return ArtifactError(source_path=source_path, reason=reason)

    return True


def format_file_size(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(num_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} {units[-1]}"


def print_artifact_status(
    package_label: str,
    artifact_label: str,
    *,
    index: int,
    total: int,
    suffix: Optional[str] = None,
    level: str = "info",
) -> None:
    if level == "info":
        compact = os.getenv("SCYTALEDROID_HARVEST_COMPACT", "1").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if compact:
            return
    message = f"    ▸ {package_label} [{index}/{total}] {artifact_label}"
    if suffix:
        message = f"{message} — {suffix}"
    show_highlight = level != "info"
    print(
        status_messages.status(
            message,
            level=level,
            show_icon=show_highlight,
            show_prefix=show_highlight,
        )
    )


def inventory_payload(inventory: InventoryRow) -> Dict[str, Optional[str]]:
    """Return a serialisable view of key inventory attributes."""

    return {
        "package_name": inventory.package_name,
        "app_label": inventory.app_label,
        "installer": inventory.installer,
        "version_name": inventory.version_name,
        "version_code": inventory.version_code,
        "category": inventory.category,
    }


def is_system_package(inventory: InventoryRow) -> bool:
    category = (inventory.category or "").lower() if inventory.category else ""
    return category != "user"


def cleanup_duplicate(dest_path: Path) -> None:
    try:
        dest_path.unlink()
    except FileNotFoundError:
        pass
    meta_path = dest_path.with_suffix(dest_path.suffix + ".meta.json")
    try:
        meta_path.unlink()
    except FileNotFoundError:
        pass
