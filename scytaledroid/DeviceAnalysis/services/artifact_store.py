"""Canonical APK store and receipt helpers."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Mapping, Sequence

from scytaledroid.Config import app_config
from scytaledroid.Utils.IO.atomic_write import atomic_write_text

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
EXTERNAL_APK_STORE_MOUNT_ROOTS = (Path("/mnt/MERCURY_DATA_V2"), Path("/mnt/MERCURY_DATA_USB"))


class ExternalApkStoreUnavailable(RuntimeError):
    """Raised when an external canonical APK store is configured but unavailable."""


class ColdApkBlobUnavailable(ExternalApkStoreUnavailable):
    """Raised when a cold canonical APK symlink cannot be resolved safely."""


def data_root() -> Path:
    """Return the resolved repository data root."""

    return Path(app_config.DATA_DIR).expanduser().resolve()


def store_root() -> Path:
    return data_root() / "store"


def apk_store_root() -> Path:
    return store_root() / "apk" / "sha256"


def analysis_apk_root() -> Path:
    return store_root() / "apk"


def receipts_root() -> Path:
    return data_root() / "receipts"


def harvest_receipts_root() -> Path:
    return receipts_root() / "harvest"


def upload_receipts_root() -> Path:
    return receipts_root() / "upload"


def upload_inbox_root() -> Path:
    return data_root() / "inbox" / "uploads"


def device_apks_root() -> Path:
    """Return ``DATA_DIR/device_apks`` (per-device pulled APK evidence tree)."""

    return data_root() / "device_apks"


def filesystem_harvest_run_label(run_id: str) -> str:
    """Map *run_id* to a single directory / receipt segment (calendar is not the root)."""

    cleaned = _safe_name(str(run_id or "").strip().replace(":", "-"))
    return (cleaned[:160] if cleaned else "harvest-run") or "harvest-run"


def compose_harvest_run_destination(*, serial: str, run_id: str) -> tuple[Path, str]:
    """Build per-run layout and receipt key.

    Artifacts land under::

        device_apks/<serial>/runs/<filesystem_harvest_run_label(run_id)>/

    *session_stamp* matches that run label so sessions are **run-scoped**, not day-scoped.
    """

    label = filesystem_harvest_run_label(run_id)
    dest_root = device_apks_root() / serial.strip() / "runs" / label
    return dest_root, label


def canonical_apk_path(sha256_digest: str, *, suffix: str = ".apk") -> Path:
    normalized = str(sha256_digest or "").strip().lower()
    if not normalized:
        raise ValueError("sha256_digest is required")
    if not suffix.startswith("."):
        suffix = f".{suffix}"
    return apk_store_root() / normalized[:2] / f"{normalized}{suffix}"


def materialize_apk(
    source_path: Path,
    *,
    sha256_digest: str,
    suffix: str = ".apk",
    move: bool = False,
) -> Path:
    """Ensure *source_path* exists in the canonical APK store and return that path."""

    ensure_external_apk_store_available()
    source = source_path.expanduser().resolve()
    if not source.exists():
        raise FileNotFoundError(source)

    logical_destination = canonical_apk_path(sha256_digest, suffix=suffix)
    if logical_destination.is_symlink():
        status = canonical_apk_blob_status(sha256_digest, suffix=suffix)
        if not status["available"]:
            _raise_cold_blob_unavailable(status)
        destination = logical_destination.resolve(strict=False)
        if source == destination:
            return logical_destination
        if move:
            source.unlink(missing_ok=True)
        return logical_destination

    destination = logical_destination.resolve(strict=False)
    destination.parent.mkdir(parents=True, exist_ok=True)

    if source == destination:
        return destination

    if destination.exists():
        if move:
            source.unlink(missing_ok=True)
        return destination

    if move:
        try:
            source.replace(destination)
            return destination
        except OSError:
            shutil.copy2(source, destination)
            source.unlink(missing_ok=True)
            return destination

    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)
    return destination


def write_harvest_receipt(
    *,
    session_label: str,
    package_name: str,
    payload: dict[str, Any],
) -> Path:
    receipt_path = harvest_receipt_path(session_label=session_label, package_name=package_name)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(receipt_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return receipt_path


def write_upload_receipt(*, upload_id: str, payload: dict[str, Any]) -> Path:
    receipt_path = upload_receipt_path(upload_id=upload_id)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(receipt_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return receipt_path


def harvest_receipt_path(*, session_label: str, package_name: str) -> Path:
    return harvest_receipts_root() / _safe_name(session_label) / f"{_safe_name(package_name)}.json"


def upload_receipt_path(*, upload_id: str) -> Path:
    return upload_receipts_root() / f"{_safe_name(upload_id)}.json"


def repo_relative_path(path: Path) -> str:
    """Return *path* relative to the current working tree when possible."""

    logical = _canonical_store_logical_repo_path(path)
    if logical is not None:
        return logical

    resolved = path.expanduser().resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def ensure_external_apk_store_available(
    *,
    apk_root: Path | None = None,
    mount_roots: Sequence[Path] | None = None,
    is_mount: Any | None = None,
) -> None:
    """Fail fast when ``data/store/apk`` points at an unmounted external store.

    This guard is intentionally narrow: local stores are allowed, and mounted
    external stores are allowed. The blocked case is a symlinked canonical APK
    root targeting one of the Mercury mountpoints while that mountpoint is not
    actually mounted, because creating parent directories then risks writing to
    the local filesystem underneath ``/mnt``.
    """

    status = external_apk_store_mount_status(
        apk_root=apk_root,
        mount_roots=mount_roots,
        is_mount=is_mount,
    )
    if status["is_symlink"] and status["external_mount_root"] and not status["external_mount_mounted"]:
        raise ExternalApkStoreUnavailable(
            "External APK store is configured but not mounted: "
            f"{status['path']} -> {status['resolved_target']} "
            f"(mountpoint {status['external_mount_root']})"
        )


def ensure_external_path_available(
    path: Path,
    *,
    description: str = "External path",
    mount_roots: Sequence[Path] | None = None,
    is_mount: Any | None = None,
) -> None:
    """Fail fast when a symlinked external path would write under an unmounted mountpoint."""

    status = external_path_mount_status(path=path, mount_roots=mount_roots, is_mount=is_mount)
    if status["is_symlink"] and status["external_mount_root"] and not status["external_mount_mounted"]:
        raise ExternalApkStoreUnavailable(
            f"{description} is configured but not mounted: "
            f"{status['path']} -> {status['resolved_target']} "
            f"(mountpoint {status['external_mount_root']})"
        )


def ensure_canonical_apk_blob_available(
    sha256_digest: str,
    *,
    suffix: str = ".apk",
    mount_roots: Sequence[Path] | None = None,
    is_mount: Any | None = None,
) -> Path:
    """Resolve a canonical APK blob or fail clearly for unavailable cold storage."""

    status = canonical_apk_blob_status(
        sha256_digest,
        suffix=suffix,
        mount_roots=mount_roots,
        is_mount=is_mount,
    )
    if status["available"]:
        return Path(str(status["resolved_path"])).expanduser().resolve()
    _raise_cold_blob_unavailable(status)


def canonical_apk_blob_status(
    sha256_digest: str,
    *,
    suffix: str = ".apk",
    mount_roots: Sequence[Path] | None = None,
    is_mount: Any | None = None,
) -> dict[str, Any]:
    """Return availability/tier status for one canonical APK blob."""

    path = canonical_apk_path(sha256_digest, suffix=suffix)
    roots = tuple(Path(p).expanduser() for p in (mount_roots or EXTERNAL_APK_STORE_MOUNT_ROOTS))
    mount_check = is_mount or os.path.ismount
    is_symlink = path.is_symlink()
    target = _symlink_target(path) if is_symlink else path.expanduser().resolve(strict=False)
    external_root = _external_mount_root_for(target, roots)
    external_mounted = bool(external_root and mount_check(str(external_root)))
    target_exists = target.exists()
    available = path.exists()
    tier = "missing"
    reason: str | None = None
    if is_symlink:
        tier = "cold" if external_root else "symlink"
        if external_root and not external_mounted:
            available = False
            reason = "cold_apk_store_unmounted"
        elif not target_exists:
            available = False
            reason = "broken_canonical_symlink"
    elif path.exists():
        tier = "hot"
    else:
        reason = "missing_canonical_blob"
    return {
        "path": path.as_posix(),
        "exists": path.exists(),
        "is_symlink": is_symlink,
        "storage_tier": tier,
        "resolved_path": target.as_posix(),
        "target_exists": target_exists,
        "external_mount_root": external_root.as_posix() if external_root else None,
        "external_mount_mounted": external_mounted,
        "available": available,
        "blocked_reason": reason,
    }


def external_apk_store_mount_status(
    *,
    apk_root: Path | None = None,
    mount_roots: Sequence[Path] | None = None,
    is_mount: Any | None = None,
) -> dict[str, Any]:
    """Return read-only mount/symlink status for the canonical APK root."""

    root = apk_root or analysis_apk_root()
    return external_path_mount_status(path=root, mount_roots=mount_roots, is_mount=is_mount)


def external_path_mount_status(
    *,
    path: Path,
    mount_roots: Sequence[Path] | None = None,
    is_mount: Any | None = None,
) -> dict[str, Any]:
    """Return read-only mount/symlink status for a potentially external path."""

    root = path
    roots = tuple(Path(p).expanduser() for p in (mount_roots or EXTERNAL_APK_STORE_MOUNT_ROOTS))
    mount_check = is_mount or os.path.ismount
    exists = root.exists()
    is_symlink = root.is_symlink()
    target = _symlink_target(root) if is_symlink else root.expanduser().resolve(strict=False)
    external_root = _external_mount_root_for(target, roots)
    mounted = bool(external_root and mount_check(str(external_root)))
    return {
        "path": root.as_posix(),
        "exists": exists,
        "is_symlink": is_symlink,
        "resolved_target": target.as_posix(),
        "target_exists": target.exists(),
        "external_mount_root": external_root.as_posix() if external_root else None,
        "external_mount_mounted": mounted,
    }


def _canonical_store_logical_repo_path(path: Path) -> str | None:
    """Map resolved external canonical APK paths back to ``data/store/apk``."""

    cwd = Path.cwd().resolve()
    logical_root = apk_store_root()
    try:
        logical_rel_to_cwd = logical_root.relative_to(cwd)
    except ValueError:
        return None
    candidate_logical = path.expanduser()
    if not candidate_logical.is_absolute():
        candidate_logical = cwd / candidate_logical
    try:
        rel = candidate_logical.relative_to(logical_root)
    except ValueError:
        pass
    else:
        return (logical_rel_to_cwd / rel).as_posix()

    resolved_root = logical_root.expanduser().resolve(strict=False)
    candidate = path.expanduser().resolve(strict=False)
    try:
        rel = candidate.relative_to(resolved_root)
    except ValueError:
        pass
    else:
        return (logical_rel_to_cwd / rel).as_posix()

    external_root = _external_mount_root_for(candidate, EXTERNAL_APK_STORE_MOUNT_ROOTS)
    if external_root is None:
        return None
    logical_suffix = _canonical_store_suffix(candidate)
    if logical_suffix is None:
        return None
    return (Path(app_config.DATA_DIR) / "store" / "apk" / logical_suffix).as_posix()


def _canonical_store_suffix(path: Path) -> Path | None:
    parts = path.parts
    marker = ("data", "store", "apk")
    for index in range(0, len(parts) - len(marker) + 1):
        if parts[index : index + len(marker)] != marker:
            continue
        suffix = Path(*parts[index + len(marker) :])
        if len(suffix.parts) == 3 and suffix.parts[0] == "sha256":
            return suffix
    return None


def _external_mount_root_for(path: Path, roots: Sequence[Path]) -> Path | None:
    resolved = path.expanduser().resolve(strict=False)
    for root in sorted(roots, key=lambda p: len(p.parts), reverse=True):
        candidate = root.expanduser().resolve(strict=False)
        try:
            resolved.relative_to(candidate)
        except ValueError:
            continue
        return candidate
    return None


def _symlink_target(path: Path) -> Path:
    raw = path.readlink()
    if raw.is_absolute():
        return raw.expanduser().resolve(strict=False)
    return (path.parent / raw).expanduser().resolve(strict=False)


def _raise_cold_blob_unavailable(status: Mapping[str, Any] | dict[str, Any]) -> None:
    reason = str(status.get("blocked_reason") or "unavailable")
    if reason == "cold_apk_store_unmounted":
        raise ColdApkBlobUnavailable(
            "Cold APK blob unavailable: Mercury drive is not mounted. "
            f"{status.get('path')} -> {status.get('resolved_path')} "
            f"(mountpoint {status.get('external_mount_root')})"
        )
    if reason == "broken_canonical_symlink":
        raise ColdApkBlobUnavailable(
            "Cold APK blob unavailable: canonical APK symlink target is missing. "
            f"{status.get('path')} -> {status.get('resolved_path')}"
        )
    raise FileNotFoundError(str(status.get("path") or "canonical APK blob"))


def _safe_name(value: str) -> str:
    cleaned = _SAFE_NAME_RE.sub("-", str(value).strip())
    cleaned = cleaned.strip("-.")
    return cleaned or "item"


def safe_filesystem_slug(value: str) -> str:
    """Stable filesystem/receipt segment (harvest session dirs, receipt filenames, run labels).

    Scripts and tools should call this instead of reimplementing sanitisation rules.
    """

    return _safe_name(value)


__all__ = [
    "analysis_apk_root",
    "apk_store_root",
    "canonical_apk_blob_status",
    "canonical_apk_path",
    "ColdApkBlobUnavailable",
    "compose_harvest_run_destination",
    "ensure_canonical_apk_blob_available",
    "ensure_external_apk_store_available",
    "ensure_external_path_available",
    "external_apk_store_mount_status",
    "external_path_mount_status",
    "ExternalApkStoreUnavailable",
    "filesystem_harvest_run_label",
    "data_root",
    "harvest_receipts_root",
    "device_apks_root",
    "harvest_receipt_path",
    "materialize_apk",
    "repo_relative_path",
    "safe_filesystem_slug",
    "receipts_root",
    "store_root",
    "upload_inbox_root",
    "upload_receipt_path",
    "upload_receipts_root",
    "write_harvest_receipt",
    "write_upload_receipt",
]
