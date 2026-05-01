# File: permission_manifest_extract.py
"""Manifest permission extraction helpers."""

from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from scytaledroid.StaticAnalysis._androguard import APK, open_apk_safely
from scytaledroid.StaticAnalysis.engine import aapt2_fallback
from scytaledroid.StaticAnalysis.engine.strings_capture import _run_with_fd_capture
from scytaledroid.Utils.LoggingUtils import logging_utils as log

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _silent_apk_call(callable_obj, default):
    try:
        result, _ = _run_with_fd_capture(callable_obj)
        return result
    except Exception:
        return default


def _extract_declared_permissions(apk: APK) -> list[tuple[str, str]]:
    """Return manifest declared permissions with their element type."""

    try:
        axml = _silent_apk_call(apk.get_android_manifest_axml, None)
        if axml is None:
            raise ValueError("missing manifest")
        xml_data = axml.get_xml()
        root = ET.fromstring(xml_data)
    except Exception:
        names = sorted(set(_silent_apk_call(apk.get_permissions, []) or []))
        return [(name, "uses-permission") for name in names]

    declared: list[tuple[str, str]] = []
    for element in root.iter():
        tag = element.tag.split("}")[-1]
        if tag not in ("uses-permission", "uses-permission-sdk-23"):
            continue
        name = element.get(f"{_ANDROID_NS}name") or element.get("name")
        if name:
            declared.append((name, tag))

    seen = set()
    ordered: list[tuple[str, str]] = []
    for item in declared:
        if item not in seen:
            seen.add(item)
            ordered.append(item)

    return ordered


def collect_permissions_and_sdk(
    apk_path: str,
) -> tuple[list[tuple[str, str]], list[dict[str, str | None]], dict[str, str | None]]:
    """Collect declared permissions, custom definitions and SDK info."""

    fallback_used = False
    fallback_meta = aapt2_fallback.extract_metadata(apk_path) if aapt2_fallback.has_aapt2() else None
    try:
        apk, warnings = open_apk_safely(apk_path)
    except Exception:
        if fallback_meta:
            declared = [(name, "uses-permission") for name in fallback_meta.get("permissions") or []]
            sdk_info = {
                "min": fallback_meta.get("min_sdk"),
                "target": fallback_meta.get("target_sdk"),
                "allow_backup": None,
                "legacy_external_storage": None,
                "fallback_used": True,
                "fallback_reason": "androguard_open_failed",
            }
            return declared, [], sdk_info
        raise
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

    defined: list[dict[str, str | None]] = []
    try:
        for entry in _silent_apk_call(apk.get_declared_permissions, ()) or ():
            name = entry.get("name") or entry.get("android:name")
            protection = entry.get("protectionLevel") or entry.get("android:protectionLevel")
            if name:
                defined.append({"name": name, "protection": protection})
    except Exception:
        pass

    min_sdk = _silent_apk_call(apk.get_min_sdk_version, None)
    target_sdk = _silent_apk_call(apk.get_target_sdk_version, None)

    # Extract key flags for modernization credit
    allow_backup = None
    legacy_ext = None
    try:
        axml = _silent_apk_call(apk.get_android_manifest_axml, None)
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

    if (not declared or min_sdk is None or target_sdk is None) and fallback_meta:
        fallback_used = True
        if not declared:
            declared = [(name, "uses-permission") for name in fallback_meta.get("permissions") or []]
        if min_sdk is None:
            min_sdk = fallback_meta.get("min_sdk")
        if target_sdk is None:
            target_sdk = fallback_meta.get("target_sdk")

    return declared, defined, {
        "min": min_sdk,
        "target": target_sdk,
        "allow_backup": allow_backup,
        "legacy_external_storage": legacy_ext,
        "fallback_used": fallback_used,
        "fallback_reason": "aapt2_badging" if fallback_used else None,
    }


def _format_permission(name: str, element_type: str) -> str:
    if element_type == "uses-permission-sdk-23":
        return f"{name} (uses-permission-sdk-23)"
    return name


__all__ = ["collect_permissions_and_sdk"]