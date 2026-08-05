from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ANDROID_TOOLS_SCRIPT = REPO_ROOT / "scripts" / "lib" / "android_tools.sh"


def test_android_tools_verifies_apksigner_with_supported_version_flag() -> None:
    source = ANDROID_TOOLS_SCRIPT.read_text(encoding="utf-8")

    assert "apksigner --version" in source
    assert "apksigner -version" not in source


def _verify_checksum(path: Path, expected: str) -> subprocess.CompletedProcess[str]:
    command = (
        f'source "{ANDROID_TOOLS_SCRIPT}"; '
        f'CMDLINE_ZIP_SHA256="{expected}"; '
        f'verify_cmdline_zip_sha256 "{path}"'
    )
    return subprocess.run(["bash", "-c", command], text=True, capture_output=True, check=False)


def test_android_tools_bootstrap_accepts_matching_download_checksum(tmp_path: Path) -> None:
    archive = tmp_path / "commandlinetools.zip"
    archive.write_bytes(b"known archive bytes")

    result = _verify_checksum(archive, hashlib.sha256(archive.read_bytes()).hexdigest())

    assert result.returncode == 0


def test_android_tools_bootstrap_rejects_mismatched_download_checksum(tmp_path: Path) -> None:
    archive = tmp_path / "commandlinetools.zip"
    archive.write_bytes(b"untrusted archive bytes")

    result = _verify_checksum(archive, "0" * 64)

    assert result.returncode != 0
    assert "SHA-256 mismatch" in result.stderr
