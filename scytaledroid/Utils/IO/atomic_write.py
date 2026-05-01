"""Atomic file write helpers for derived artifacts.

These helpers are intended for *derived* JSON/CSV/manifests/receipts where partial
writes can corrupt downstream tooling if a process is interrupted.

Do not use for large raw evidence artifacts (e.g., PCAPs).
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            dir=str(path.parent),
            prefix=f".{path.name}.tmp.",
        ) as tmp:
            tmp_path = tmp.name
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_path, path)
    finally:
        if tmp_path:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    atomic_write_bytes(path, text.encode(encoding))


def atomic_copyfile(src: Path, dst: Path) -> None:
    if not src.exists():
        raise FileNotFoundError(str(src))
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            dir=str(dst.parent),
            prefix=f".{dst.name}.tmp.",
        ) as tmp:
            tmp_path = tmp.name
        shutil.copyfile(src, tmp_path)
        os.replace(tmp_path, dst)
    finally:
        if tmp_path:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass


__all__ = ["atomic_write_bytes", "atomic_write_text", "atomic_copyfile"]

