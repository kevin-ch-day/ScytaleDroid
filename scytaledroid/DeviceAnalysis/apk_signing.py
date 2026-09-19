"""Extract signing-certificate SHA-256 from a harvested APK file.

Inventory dumpsys on current Android 15 devices does not emit a 64-character
cert digest, so harvest must read the APK itself. Prefer the lineage signer
whose min/max SDK covers the running device API; fall back to ``Signer #1``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .identity import normalize_hex_digest

_DIGEST_RE = re.compile(r"certificate SHA-256 digest:\s*([0-9A-Fa-f]{64})", re.I)
_MINSDK_RE = re.compile(r"minSdkVersion\s*=\s*(\d+)", re.I)
_MAXSDK_RE = re.compile(r"maxSdkVersion\s*=\s*(\d+)", re.I)
_DEFAULT_DEVICE_SDK = 35


def _find_apksigner() -> str | None:
    found = shutil.which("apksigner")
    if found:
        return found
    sdk = str(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "").strip()
    if not sdk:
        return None
    tools = Path(sdk) / "build-tools"
    if not tools.is_dir():
        return None
    candidates = sorted(tools.glob("*/apksigner"), reverse=True)
    for path in candidates:
        if path.is_file():
            return str(path)
    return None


def parse_apksigner_cert_sha256(text: str, *, device_sdk: int = _DEFAULT_DEVICE_SDK) -> str | None:
    """Return the primary signer SHA-256 from ``apksigner verify --print-certs`` output."""

    numbered: str | None = None
    covering: list[tuple[int, str]] = []
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or "source stamp" in line.lower():
            continue
        digest_match = _DIGEST_RE.search(line)
        if not digest_match:
            continue
        digest = normalize_hex_digest(digest_match.group(1))
        if not digest:
            continue
        if line.lower().startswith("signer #1 "):
            numbered = digest
        min_sdk = int(_MINSDK_RE.search(line).group(1)) if _MINSDK_RE.search(line) else -1
        max_sdk = int(_MAXSDK_RE.search(line).group(1)) if _MAXSDK_RE.search(line) else 10**9
        if min_sdk < 0 or min_sdk <= int(device_sdk) <= max_sdk:
            covering.append((min_sdk, digest))
    # Lineage ranges that cover the device API are more accurate than Signer #1
    # (often the oldest v1/v2 cert on rotation-signed APKs).
    if covering:
        covering.sort(key=lambda item: item[0], reverse=True)
        return covering[0][1]
    return numbered


def _looks_like_zip(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def extract_apk_cert_sha256(apk_path: str | Path, *, device_sdk: int = _DEFAULT_DEVICE_SDK) -> str | None:
    """Best-effort SHA-256 of the APK signing certificate via apksigner."""

    path = Path(apk_path)
    if not path.is_file() or not _looks_like_zip(path):
        return None
    apksigner = _find_apksigner()
    if not apksigner:
        return None
    try:
        completed = subprocess.run(
            [apksigner, "verify", "--print-certs", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except Exception:
        return None
    return parse_apksigner_cert_sha256(
        f"{completed.stdout or ''}\n{completed.stderr or ''}",
        device_sdk=device_sdk,
    )


__all__ = ["extract_apk_cert_sha256", "parse_apksigner_cert_sha256"]
