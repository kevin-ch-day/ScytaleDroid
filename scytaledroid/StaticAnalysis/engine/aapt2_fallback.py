"""Best-effort APK metadata extraction via aapt2."""

from __future__ import annotations

import shutil
import subprocess
from typing import Dict, List


def has_aapt2() -> bool:
    return shutil.which("aapt2") is not None


def dump_badging(apk_path: str) -> str | None:
    aapt2 = shutil.which("aapt2")
    if not aapt2:
        return None
    try:
        return subprocess.check_output(
            [aapt2, "dump", "badging", apk_path],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
    except Exception:
        return None


def parse_badging(text: str) -> Dict[str, object]:
    data: Dict[str, object] = {
        "package_name": None,
        "version_code": None,
        "version_name": None,
        "min_sdk": None,
        "target_sdk": None,
        "app_label": None,
        "permissions": [],
    }
    perms: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            parts = line.split()
            for part in parts:
                if part.startswith("name="):
                    data["package_name"] = part.split("=", 1)[1].strip("'\"")
                elif part.startswith("versionCode="):
                    data["version_code"] = part.split("=", 1)[1].strip("'\"")
                elif part.startswith("versionName="):
                    data["version_name"] = part.split("=", 1)[1].strip("'\"")
        elif line.startswith("sdkVersion:"):
            data["min_sdk"] = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("targetSdkVersion:"):
            data["target_sdk"] = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("application-label:"):
            data["app_label"] = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("uses-permission:"):
            perm = line.split(":", 1)[1].strip().strip("'\"")
            if perm:
                perms.append(perm)
    data["permissions"] = sorted(set(perms))
    return data


def extract_metadata(apk_path: str) -> Dict[str, object] | None:
    text = dump_badging(apk_path)
    if not text:
        return None
    return parse_badging(text)


__all__ = ["has_aapt2", "dump_badging", "parse_badging", "extract_metadata"]
