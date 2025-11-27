"""Helpers for normalising package entries used in inventory metadata."""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence


def normalize_scope_entries(scope_packages: Sequence[object]) -> List[Dict[str, object]]:
    normalized: List[Dict[str, object]] = []
    for entry in scope_packages:
        package_name: Optional[str]
        version_code: Optional[object]

        if isinstance(entry, dict):
            package_name = entry.get("package_name") if isinstance(entry.get("package_name"), str) else None
            version_code = entry.get("version_code")
        else:
            package_name = getattr(entry, "package_name", None)
            if not isinstance(package_name, str):
                package_name = None
            version_code = getattr(entry, "version_code", None)

        if not package_name:
            continue

        normalized.append({"package_name": package_name, "version_code": version_code})

    return normalized


def normalise_version_code(value: Optional[object]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return str(int(value))
    if isinstance(value, str):
        candidate = value.strip()
        return candidate or None
    return str(value)


def display_version(version_code: Optional[object], version_name: Optional[object]) -> Optional[str]:
    code = normalise_version_code(version_code)
    if code:
        return code
    if isinstance(version_name, str):
        candidate = version_name.strip()
        if candidate:
            return candidate
    return None

