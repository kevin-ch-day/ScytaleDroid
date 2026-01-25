# File: permission_manifest_extract.py
"""Manifest permission extraction helpers."""

from __future__ import annotations

from xml.etree import ElementTree as ET
from typing import Dict, List, Tuple
import re

from scytaledroid.StaticAnalysis._androguard import APK, open_apk_safely
from scytaledroid.Utils.LoggingUtils import logging_utils as log

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _extract_declared_permissions(apk: APK) -> List[Tuple[str, str]]:
    """Return manifest declared permissions with their element type."""

    try:
        axml = apk.get_android_manifest_axml()
        if axml is None:
            raise ValueError("missing manifest")
        xml_data = axml.get_xml()
        root = ET.fromstring(xml_data)
    except Exception:
        names = sorted(set(apk.get_permissions() or []))
        return [(name, "uses-permission") for name in names]

    declared: List[Tuple[str, str]] = []
    for element in root.iter():
        tag = element.tag.split("}")[-1]
        if tag not in ("uses-permission", "uses-permission-sdk-23"):
            continue
        name = element.get(f"{_ANDROID_NS}name") or element.get("name")
        if name:
            declared.append((name, tag))

    seen = set()
    ordered: List[Tuple[str, str]] = []
    for item in declared:
        if item not in seen:
            seen.add(item)
            ordered.append(item)

    return ordered


def collect_permissions_and_sdk(
    apk_path: str,
) -> Tuple[List[Tuple[str, str]], List[Dict[str, str | None]], Dict[str, str | None]]:
    """Collect declared permissions, custom definitions and SDK info."""

    apk, warnings = open_apk_safely(apk_path)
    if warnings:
        counts = []
        for line in warnings:
            match = re.search(r"Count:\s*(\d+)", line)
            if match:
                try:
                    counts.append(int(match.group(1)))
                except ValueError:
                    continue
        log.warning(
            "Resource table parsing emitted bounds warnings",
            category="static_analysis",
            extra={
                "event": "permissions.resource_bounds_warning",
                "apk_path": apk_path,
                "package_name": apk.get_package(),
                "warning_lines": warnings,
                "count_values": counts,
            },
        )

    try:
        declared = _extract_declared_permissions(apk)
    except Exception:
        declared = []

    defined: List[Dict[str, str | None]] = []
    try:
        for entry in apk.get_declared_permissions() or ():
            name = entry.get("name") or entry.get("android:name")
            protection = entry.get("protectionLevel") or entry.get("android:protectionLevel")
            if name:
                defined.append({"name": name, "protection": protection})
    except Exception:
        pass

    try:
        min_sdk = apk.get_min_sdk_version()
    except Exception:
        min_sdk = None
    try:
        target_sdk = apk.get_target_sdk_version()
    except Exception:
        target_sdk = None

    # Extract key flags for modernization credit
    allow_backup = None
    legacy_ext = None
    try:
        axml = apk.get_android_manifest_axml()
        if axml is not None:
            root = ET.fromstring(axml.get_xml())
            app_nodes = root.findall("application")
            for app in app_nodes:
                ab = app.get(f"{_ANDROID_NS}allowBackup") or app.get("allowBackup")
                if ab is not None:
                    allow_backup = True if str(ab).lower() in {"1", "true", "yes"} else False
                rles = app.get(f"{_ANDROID_NS}requestLegacyExternalStorage") or app.get("requestLegacyExternalStorage")
                if rles is not None:
                    legacy_ext = True if str(rles).lower() in {"1", "true", "yes"} else False
                break
    except Exception:
        pass

    return declared, defined, {
        "min": min_sdk,
        "target": target_sdk,
        "allow_backup": allow_backup,
        "legacy_external_storage": legacy_ext,
    }


def _format_permission(name: str, element_type: str) -> str:
    if element_type == "uses-permission-sdk-23":
        return f"{name} (uses-permission-sdk-23)"
    return name


__all__ = ["collect_permissions_and_sdk"]
