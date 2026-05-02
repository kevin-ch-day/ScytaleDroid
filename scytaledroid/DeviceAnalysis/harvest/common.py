"""Shared helpers for APK harvest implementations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.adb import client as adb_client
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.IO.atomic_write import atomic_write_text
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .models import ArtifactError, InventoryRow

_EVIDENCE_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


def _harvest_evidence_slug(text: str, *, default: str, max_len: int) -> str:
    raw = str(text or "").strip()
    if not raw:
        return default
    slug = _EVIDENCE_SLUG.sub("-", raw).strip("-.")
    slug = slug or default
    return slug[:max_len]


def package_evidence_leaf_name(inventory: InventoryRow) -> str:
    """Directory name under *package_name/* grouping by app title + version."""

    app = (inventory.app_label or "").strip()
    if not app:
        tail = inventory.package_name.rsplit(".", 1)[-1] if "." in inventory.package_name else inventory.package_name
        app = str(tail).strip() or "app"
    safe_app = _harvest_evidence_slug(app, default="app", max_len=56)
    vc = _harvest_evidence_slug(str(inventory.version_code or ""), default="unknown", max_len=28)
    vn_raw = str(inventory.version_name or "").strip()
    if vn_raw:
        safe_vn = _harvest_evidence_slug(vn_raw, default="na", max_len=48)
        leaf = f"{safe_app}_v{vc}_{safe_vn}"
    else:
        leaf = f"{safe_app}_v{vc}"
    return leaf[:140]


def package_evidence_dir(dest_root: Path, inventory: InventoryRow) -> Path:
    """Per-package directory: ``<dest_root>/<package>/<app>_v<code>_<versionName>/``."""

    return dest_root / inventory.package_name / package_evidence_leaf_name(inventory)


def iter_harvest_package_manifest_paths(root: Path) -> list[Path]:
    """Return sorted paths to ``harvest_package_manifest.json`` under *root*.

    If *root* does not exist, returns an empty list (no exception).
    """

    base = root.expanduser().resolve()
    if not base.exists():
        return []
    return sorted(p for p in base.rglob("harvest_package_manifest.json") if p.is_file())


DEFAULT_META_FIELDS: tuple[str, ...] = (
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
    "artifact_kind",
    "canonical_store_path",
)


def _harvest_base_dir() -> Path:
    """Return the absolute base directory for harvested APKs."""

    return (Path(app_config.DATA_DIR) / "device_apks").resolve()


def normalise_local_path(dest_path: Path) -> str:
    """Return the harvest-relative path for *dest_path*."""

    base = _harvest_base_dir().resolve()
    try:
        dest_abs = dest_path.expanduser().absolute()
        return dest_abs.relative_to(base).as_posix()
    except ValueError:
        # Fallback when outside the harvest tree or cross-device (follow symlinks)
        return dest_path.expanduser().resolve().as_posix()


def replace_session_apk_with_symlink_to_canonical(
    *,
    session_artifact_path: Path,
    canonical_absolute: Path,
    enabled: bool,
) -> None:
    """After materializing *canonical_absolute*, optionally drop the duplicated session copy."""

    if not enabled or not canonical_absolute.exists():
        return
    try:
        if not session_artifact_path.exists():
            return
        if hasattr(os, "samefile") and os.path.samefile(session_artifact_path, canonical_absolute):
            return
        rel = Path(
            os.path.relpath(
                canonical_absolute.resolve(),
                session_artifact_path.expanduser().absolute().parent,
            )
        )
        session_artifact_path.unlink()
        session_artifact_path.symlink_to(rel, target_is_directory=False)
    except OSError as exc:
        log.warning(
            f"Thin session symlink skipped for {session_artifact_path}: {exc}",
            category="filesystem",
        )


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
    meta_fields: tuple[str, ...] = DEFAULT_META_FIELDS
    pull_mode: str = "inventory"
    # When true, re-pull artifacts even if the destination path already exists.
    # This is required for paper-grade "full refresh" harvests where filenames
    # may be stable (same version_code) but the on-device artifact changed.
    overwrite_existing: bool = False
    thin_session: bool = False


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

    # OSS posture: DB is optional. If the DB backend is disabled, never attempt DB writes.
    # This prevents harvest from skipping packages due to DB connectivity/schema errors.
    write_db_cfg = bool(getattr(config, "HARVEST_WRITE_DB", True))
    db_enabled = False
    try:
        from scytaledroid.Database.db_core import (
            db_config as core_db_config,  # local import (optional DB)
        )

        db_enabled = bool(core_db_config.db_enabled())
    except Exception:
        db_enabled = False
    write_db = bool(write_db_cfg and db_enabled)
    write_meta = bool(getattr(config, "HARVEST_WRITE_META", True))

    meta_fields_raw = getattr(config, "HARVEST_META_FIELDS", DEFAULT_META_FIELDS)
    if isinstance(meta_fields_raw, str):
        candidates = [part.strip() for part in meta_fields_raw.split(",")]
    elif isinstance(meta_fields_raw, (list, tuple)):
        candidates = [str(field).strip() for field in meta_fields_raw]
    else:
        candidates = []

    if candidates:
        fields: tuple[str, ...] = tuple(field for field in candidates if field)
        meta_fields = fields or DEFAULT_META_FIELDS
    else:
        meta_fields = DEFAULT_META_FIELDS

    thin_session = os.getenv("SCYTALEDROID_HARVEST_THIN_SESSION", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    return HarvestOptions(
        dedupe_sha256=dedupe,
        keep_last=keep_last,
        write_db=write_db,
        write_meta=write_meta,
        meta_fields=meta_fields,
        pull_mode=pull_mode,
        overwrite_existing=False,
        thin_session=thin_session,
    )


@dataclass
class DedupeTracker:
    """Track sha256 collisions and determine whether to keep artifacts."""

    options: HarvestOptions
    counts: MutableMapping[str, int] = field(default_factory=dict)
    skipped: int = 0

    def register(self, sha256: str) -> tuple[bool, int]:
        """Record *sha256* and return (keep, occurrence_index)."""

        current = self.counts.get(sha256, 0) + 1
        self.counts[sha256] = current
        if not self.options.dedupe_sha256:
            return True, current
        if current <= self.options.keep_last:
            return True, current
        self.skipped += 1
        return False, current


def compute_hashes(dest_path: Path) -> dict[str, str]:
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
    extra: Mapping[str, object | None] = None,
) -> Path | None:
    """Write a ``*.meta.json`` sidecar next to *dest_path* when enabled."""

    if not options.write_meta:
        return None

    captured_at = datetime.now(UTC).isoformat()
    payload: dict[str, object] = {
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


def write_json_manifest(path: Path, payload: Mapping[str, object]) -> Path:
    """Write a small JSON manifest atomically."""

    atomic_write_text(path, json.dumps(dict(payload), indent=2, sort_keys=True) + "\n")
    return path


def adb_pull(
    *,
    adb_path: str,
    serial: str,
    source_path: str,
    dest_path: Path,
    package_name: str,
    verbose: bool,
    overwrite_existing: bool = False,
):
    """Ensure *dest_path* exists locally by issuing ``adb pull``."""

    if dest_path.exists() and not overwrite_existing:
        return True
    if dest_path.exists() and overwrite_existing:
        # Full refresh mode: remove the existing artifact so adb pull writes the new one.
        try:
            dest_path.unlink()
        except Exception as exc:
            return ArtifactError(source_path=source_path, reason=f"overwrite_unlink_failed: {exc}")

    command = [adb_path, "-s", serial, "pull", source_path, str(dest_path)]
    if verbose:
        print(status_messages.status(f"Executing: {' '.join(command)}", level="info"))
    try:
        completed = adb_client.run_adb_command(
            command[1:],  # drop adb binary
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
        if _is_stale_path_error(stderr):
            log.warning(
                f"adb pull hit stale path for {package_name}: {source_path}",
                category="device",
            )
            return ArtifactError(source_path=source_path, reason="path_stale")
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


def _is_stale_path_error(message: str) -> bool:
    lowered = message.lower()
    return "failed to stat remote object" in lowered or "no such file or directory" in lowered


def print_artifact_status(
    package_label: str,
    artifact_label: str,
    *,
    index: int,
    total: int,
    suffix: str | None = None,
    level: str = "info",
) -> None:
    compact = os.getenv("SCYTALEDROID_HARVEST_COMPACT", "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if compact and level in {"info", "success"}:
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


def inventory_payload(inventory: InventoryRow) -> dict[str, str | None]:
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
