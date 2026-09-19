"""Extract the application label from a harvested APK via aapt2.

Android 15 dumpsys package output no longer includes application-label, so
harvest must read the APK itself after pull. Package-equal labels are discarded.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def _find_aapt2() -> str | None:
    found = shutil.which("aapt2")
    if found:
        return found
    sdk = str(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "").strip()
    if not sdk:
        return None
    tools = Path(sdk) / "build-tools"
    if not tools.is_dir():
        return None
    candidates = sorted(tools.glob("*/aapt2"), reverse=True)
    for path in candidates:
        if path.is_file():
            return str(path)
    return None


def _looks_like_zip(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def parse_application_label(text: str, *, package_name: str | None = None) -> str | None:
    """Return application-label from ``aapt2 dump badging`` output."""

    label: str | None = None
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if line.startswith("application-label:"):
            label = line.split(":", 1)[1].strip().strip("'\"")
            break
        if label is None and line.startswith("application-label-"):
            label = line.split(":", 1)[1].strip().strip("'\"")
    cleaned = str(label or "").strip()
    if not cleaned:
        return None
    if package_name and cleaned.lower() == str(package_name).strip().lower():
        return None
    return cleaned


def extract_apk_application_label(
    apk_path: str | Path,
    *,
    package_name: str | None = None,
) -> str | None:
    """Best-effort application label from a harvested APK."""

    path = Path(apk_path)
    if not path.is_file() or not _looks_like_zip(path):
        return None
    aapt2 = _find_aapt2()
    if not aapt2:
        return None
    try:
        completed = subprocess.run(
            [aapt2, "dump", "badging", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception:
        return None
    return parse_application_label(
        f"{completed.stdout or ''}\n{completed.stderr or ''}",
        package_name=package_name,
    )


__all__ = ["extract_apk_application_label", "parse_application_label"]
