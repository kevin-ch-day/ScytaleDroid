"""Bulk ADB parsers to reduce per-package shell calls during inventory collection.

This module is intentionally UI-free and can be wired into package_collection
to replace per-package `adb shell` invocations with one or two bulk queries
(`pm list packages`, optional `dumpsys package`) and local parsing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from scytaledroid.Utils.LoggingUtils import logging_utils as log
from .. import adb_utils


@dataclass
class BulkPackageEntry:
    package_name: str
    apk_path: Optional[str]
    user: Optional[str]
    uid: Optional[int]


_PM_LIST_RE = re.compile(
    r"package:(?P<path>[^=]+)=(?P<name>[^ ]+)(?:\s+uid:(?P<uid>\d+))?(?:\s+user:(?P<user>[\w-]+))?",
    re.IGNORECASE,
)


def _parse_pm_list_line(line: str) -> Optional[BulkPackageEntry]:
    line = line.strip()
    if not line or not line.startswith("package:"):
        return None
    match = _PM_LIST_RE.match(line)
    if not match:
        return None
    name = match.group("name")
    if not name:
        return None
    apk_path = match.group("path")
    uid = match.group("uid")
    user = match.group("user")
    try:
        uid_int = int(uid) if uid else None
    except ValueError:
        uid_int = None
    return BulkPackageEntry(package_name=name, apk_path=apk_path, user=user, uid=uid_int)


def list_packages_bulk(serial: str) -> List[BulkPackageEntry]:
    """Return package entries via a single `pm list packages -f -U` call."""
    output = adb_utils.run_shell(
        serial,
        ["pm", "list", "packages", "-f", "-U"],
        check=False,
    )
    entries: List[BulkPackageEntry] = []
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


def parse_dumpsys_package(raw: str) -> Dict[str, Dict[str, object]]:
    """Parse a dumpsys package blob into a mapping of package_name -> metadata.

    This is a minimal scaffold; fill it out if/when we need richer metadata
    without per-package dumpsys calls.
    """
    results: Dict[str, Dict[str, object]] = {}
    current: Optional[str] = None
    for line in raw.splitlines():
        m = _DUMPSYS_PKG_RE.search(line)
        if m:
            current = m.group("name")
            results[current] = {}
            continue
        # Extend here with heuristics as needed (installer, firstInstallTime, flags)
    return results


def dumpsys_package_bulk(serial: str) -> Dict[str, Dict[str, object]]:
    """Fetch and parse `dumpsys package` once for richer metadata (optional)."""
    raw = adb_utils.run_shell(serial, ["dumpsys", "package"], check=False)
    if not raw:
        return {}
    return parse_dumpsys_package(raw)


__all__ = [
    "BulkPackageEntry",
    "list_packages_bulk",
    "dumpsys_package_bulk",
    "parse_dumpsys_package",
]
