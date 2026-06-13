"""Bulk ADB parsers to reduce per-package shell calls during inventory collection.

This module is intentionally UI-free and can be wired into package_collection
to replace per-package `adb shell` invocations with one or two bulk queries
(`pm list packages`, optional `dumpsys package`) and local parsing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.Utils.LoggingUtils import logging_utils as log


@dataclass
class BulkPackageEntry:
    package_name: str
    apk_path: str | None
    user: str | None
    uid: int | None
    installer: str | None = None
    version_code: str | None = None


def _parse_pm_list_line(line: str) -> BulkPackageEntry | None:
    line = line.strip()
    if not line or not line.startswith("package:"):
        return None

    tokens = line.split()
    package_token = tokens[0]
    payload = package_token.removeprefix("package:").strip()
    apk_path: str | None = None
    name = payload
    if "=" in payload:
        apk_path, name = payload.rsplit("=", 1)
        apk_path = apk_path.strip() or None
    name = name.strip()
    if not name:
        return None

    uid: str | None = None
    user: str | None = None
    installer: str | None = None
    version_code: str | None = None
    for token in tokens[1:]:
        if token.startswith("uid:") or token.startswith("uid="):
            uid = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]
        elif token.startswith("user:") or token.startswith("user="):
            user = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]
        elif token.startswith("installer=") or token.startswith("installerPackageName="):
            installer = token.split("=", 1)[1].strip() or None
        elif token.startswith("versionCode:") or token.startswith("versionCode="):
            version_code = token.split(":", 1)[1] if ":" in token else token.split("=", 1)[1]

    try:
        uid_int = int(uid) if uid else None
    except ValueError:
        uid_int = None
    return BulkPackageEntry(
        package_name=name,
        apk_path=apk_path,
        user=user,
        uid=uid_int,
        installer=installer,
        version_code=(version_code.strip() or None) if version_code else None,
    )


def list_packages_bulk(serial: str) -> list[BulkPackageEntry]:
    """Return package entries via a single `pm list packages` bulk call."""
    output = adb_shell.run_shell(
        serial,
        ["pm", "list", "packages", "-f", "-i", "-U", "--show-versioncode"],
        check=False,
    )
    entries: list[BulkPackageEntry] = []
    if not output:
        log.warning("Bulk pm list returned no output", category="inventory")
        return entries
    for line in output.splitlines():
        entry = _parse_pm_list_line(line)
        if entry:
            entries.append(entry)
    return entries


# Optional: dumpsys package parsing (minimal skeleton)
_DUMPSYS_PKG_RE = re.compile(r"Package \[(?P<name>[^\]]+)\]")


def parse_dumpsys_package(raw: str) -> dict[str, dict[str, object]]:
    """Parse a dumpsys package blob into a mapping of package_name -> metadata.

    This is a minimal scaffold; fill it out if/when we need richer metadata
    without per-package dumpsys calls.
    """
    results: dict[str, dict[str, object]] = {}
    current: str | None = None
    for line in raw.splitlines():
        m = _DUMPSYS_PKG_RE.search(line)
        if m:
            current = m.group("name")
            results[current] = {}
            continue
        # Extend here with heuristics as needed (installer, firstInstallTime, flags)
    return results


def dumpsys_package_bulk(serial: str) -> dict[str, dict[str, object]]:
    """Fetch and parse `dumpsys package` once for richer metadata (optional)."""
    raw = adb_shell.run_shell(serial, ["dumpsys", "package"], check=False)
    if not raw:
        return {}
    return parse_dumpsys_package(raw)


__all__ = [
    "BulkPackageEntry",
    "list_packages_bulk",
    "dumpsys_package_bulk",
    "parse_dumpsys_package",
]
