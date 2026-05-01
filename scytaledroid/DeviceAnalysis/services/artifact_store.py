"""Canonical APK store and receipt helpers."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Utils.IO.atomic_write import atomic_write_text

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


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


def legacy_harvest_root() -> Path:
    return data_root() / "device_apks"


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

    source = source_path.expanduser().resolve()
    if not source.exists():
        raise FileNotFoundError(source)

    destination = canonical_apk_path(sha256_digest, suffix=suffix).resolve()
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

    resolved = path.expanduser().resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _safe_name(value: str) -> str:
    cleaned = _SAFE_NAME_RE.sub("-", str(value).strip())
    cleaned = cleaned.strip("-.")
    return cleaned or "item"


__all__ = [
    "analysis_apk_root",
    "apk_store_root",
    "canonical_apk_path",
    "data_root",
    "harvest_receipts_root",
    "harvest_receipt_path",
    "legacy_harvest_root",
    "materialize_apk",
    "repo_relative_path",
    "receipts_root",
    "store_root",
    "upload_inbox_root",
    "upload_receipt_path",
    "upload_receipts_root",
    "write_harvest_receipt",
    "write_upload_receipt",
]
