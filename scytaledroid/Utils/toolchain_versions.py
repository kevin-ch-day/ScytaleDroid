"""Capture toolchain versions for deterministic artifacts.

Phase E / paper toolchain posture:
- We guarantee reproducibility inside a pinned toolchain (Python + NumPy + tshark, etc.).
- Outside that toolchain, outputs are best-effort and may drift.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from typing import Any


def _run_version_cmd(argv: list[str], *, timeout_s: float = 5.0) -> str | None:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except Exception:
        return None
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    text = out or err
    if not text:
        return None
    # Keep the first line to avoid noisy multi-line banners.
    return text.splitlines()[0].strip() or None


def _pkg_version(dist_name: str) -> str | None:
    try:
        from importlib.metadata import version

        return version(dist_name)
    except Exception:
        return None


def gather_toolchain_versions() -> dict[str, Any]:
    """Return a JSON-serializable toolchain snapshot."""

    tshark = shutil.which("tshark")
    capinfos = shutil.which("capinfos")
    return {
        "python": {
            "version": sys.version.splitlines()[0],
            "executable": sys.executable,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "platform": platform.platform(),
        },
        "packages": {
            "numpy": _pkg_version("numpy"),
            "scikit-learn": _pkg_version("scikit-learn"),
            "openpyxl": _pkg_version("openpyxl"),
            "matplotlib": _pkg_version("matplotlib"),
        },
        "tools": {
            "tshark": {"path": tshark, "version": _run_version_cmd([tshark, "-v"]) if tshark else None},
            "capinfos": {
                "path": capinfos,
                "version": _run_version_cmd([capinfos, "-v"]) if capinfos else None,
            },
        },
        "env": {
            "SCYTALEDROID_TSHARK_TIMEOUT_S": os.getenv("SCYTALEDROID_TSHARK_TIMEOUT_S"),
        },
    }


__all__ = ["gather_toolchain_versions"]

