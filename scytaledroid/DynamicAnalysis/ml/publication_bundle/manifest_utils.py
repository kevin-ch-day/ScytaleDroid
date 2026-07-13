"""Shared manifest and file helpers for runtime ML publication bundles."""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_stream(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_required(src: Path, dest: Path, *, overwrite: bool) -> None:
    if not src.exists():
        raise RuntimeError(f"Missing required input for bundle: {src}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and not overwrite:
        return
    dest.write_bytes(src.read_bytes())


__all__ = ["copy_required", "sha256_stream"]
