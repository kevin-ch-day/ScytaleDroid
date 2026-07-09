"""Best-effort APK metadata extraction via aapt2."""

from __future__ import annotations

import re
import shutil
import subprocess


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


def dump_resources(apk_path: str, *, timeout: int = 30) -> str | None:
    aapt2 = shutil.which("aapt2")
    if not aapt2:
        return None
    try:
        return subprocess.check_output(
            [aapt2, "dump", "resources", apk_path],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return None


_RESOURCE_LINE_RE = re.compile(r"^\s*resource\s+0x[0-9a-fA-F]+\s+string/(?P<name>\S+)")
_VALUE_LINE_RE = re.compile(r"^\s*\((?P<locale>[^)]*)\)\s+(?P<value>\".*\")\s*$")
_ESCAPE_RE = re.compile(r"\\([\\\"'nrt])")


def _decode_aapt2_quoted_value(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]

    def _replace(match: re.Match[str]) -> str:
        token = match.group(1)
        return {
            "\\": "\\",
            '"': '"',
            "'": "'",
            "n": "\n",
            "r": "\r",
            "t": "\t",
        }.get(token, match.group(0))

    return _ESCAPE_RE.sub(_replace, text)


def parse_resource_strings(text: str) -> list[dict[str, str]]:
    """Parse string resources from ``aapt2 dump resources`` output."""

    rows: list[dict[str, str]] = []
    current_name = ""
    for raw in text.splitlines():
        resource_match = _RESOURCE_LINE_RE.match(raw)
        if resource_match:
            current_name = resource_match.group("name").strip()
            continue
        if not current_name:
            continue
        value_match = _VALUE_LINE_RE.match(raw)
        if not value_match:
            continue
        value = _decode_aapt2_quoted_value(value_match.group("value")).strip()
        if not value:
            continue
        rows.append(
            {
                "name": current_name,
                "locale": value_match.group("locale").strip(),
                "value": value,
            }
        )
    return rows


def extract_resource_strings(apk_path: str, *, timeout: int = 30) -> list[dict[str, str]]:
    text = dump_resources(apk_path, timeout=timeout)
    if not text:
        return []
    return parse_resource_strings(text)


def parse_badging(text: str) -> dict[str, object]:
    data: dict[str, object] = {
        "package_name": None,
        "version_code": None,
        "version_name": None,
        "min_sdk": None,
        "target_sdk": None,
        "app_label": None,
        "permissions": [],
    }
    perms: list[str] = []
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


def extract_metadata(apk_path: str) -> dict[str, object] | None:
    text = dump_badging(apk_path)
    if not text:
        return None
    return parse_badging(text)


__all__ = [
    "has_aapt2",
    "dump_badging",
    "dump_resources",
    "parse_badging",
    "parse_resource_strings",
    "extract_metadata",
    "extract_resource_strings",
]
