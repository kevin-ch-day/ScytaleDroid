"""Minimal helpers for printing manifest permissions directly to the console."""

from __future__ import annotations

from xml.etree import ElementTree as ET
from typing import Dict, List, Sequence, Tuple, Mapping, Optional

from scytaledroid.StaticAnalysis._androguard import APK

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
        tag = element.tag.split('}')[-1]
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

    apk = APK(apk_path)

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

    return declared, defined, {"min": min_sdk, "target": target_sdk}


def _format_permission(name: str, element_type: str) -> str:
    if element_type == "uses-permission-sdk-23":
        return f"{name} (uses-permission-sdk-23)"
    return name


def _fetch_protections(names: Sequence[str]) -> Mapping[str, Optional[str]]:
    """Best-effort DB lookup of framework protection levels for given names.

    Returns a mapping of perm_name -> protection or None. On any error, returns
    an empty mapping.
    """
    try:  # optional DB dependency
        from scytaledroid.Database.db_func.detected_permissions import (
            framework_protection_map,
        )

        return framework_protection_map(names)
    except Exception:
        return {}


def print_permissions_block(
    package_name: str,
    artifact_label: str,
    declared: Sequence[Tuple[str, str]],
    defined: Sequence[Dict[str, str | None]],
    sdk: Dict[str, str | None],
) -> None:
    """Print a narrow permission summary directly to stdout."""

    print(f"Permission Analysis — {package_name}")
    print(f"Artifact: {artifact_label}")
    min_sdk = sdk.get("min") or "-"
    target_sdk = sdk.get("target") or "-"
    print(f"SDKs: min={min_sdk}  target={target_sdk}")
    print("-" * 40)

    # Deduplicate declared names (ignore sdk-23 suffix for risk lookup)
    unique_declared: List[Tuple[str, str]] = []
    seen: set[Tuple[str, str]] = set()
    for name, element_type in declared:
        key = (name, element_type)
        if key not in seen:
            seen.add(key)
            unique_declared.append((name, element_type))

    # Protective annotations from framework table when available
    names_only = [n for n, _ in unique_declared if n.startswith("android.")]
    protection_map = _fetch_protections(names_only)

    android_perms: List[str] = []
    custom_perms: List[str] = []
    risk_counts: Dict[str, int] = {"dangerous": 0, "signature": 0, "normal": 0, "other": 0}
    for name, element_type in unique_declared:
        formatted = _format_permission(name, element_type)
        if name.startswith("android."):
            prot = protection_map.get(name)
            if prot:
                tag = f" [{prot}]"
                risk_counts[prot] = risk_counts.get(prot, 0) + 1
            else:
                tag = ""
                risk_counts["other"] = risk_counts.get("other", 0) + 1
            android_perms.append(f"{formatted}{tag}")
        else:
            custom_perms.append(formatted)

    if android_perms:
        print(f"Android permissions ({len(android_perms)}):")
        for permission in android_perms:
            print(f"  {permission}")

    if custom_perms:
        print(f"Custom/vendor permissions ({len(custom_perms)}):")
        for permission in custom_perms:
            print(f"  {permission}")

    if defined:
        print("\nCustom permissions declared:")
        for entry in defined:
            name = entry.get("name")
            protection = entry.get("protection") or "-"
            if name:
                print(f"  {name}  (protection={protection})")

    total_declared = len(unique_declared)
    print(
        "\nCounts: total_declared="
        f"{total_declared}  android={len(android_perms)}  custom={len(custom_perms)}  "
        f"custom_defined={len(defined)}"
    )
    # Risk breakdown (android only)
    if names_only:
        summary = ", ".join(
            f"{k}={v}" for k, v in (
                ("dangerous", risk_counts.get("dangerous", 0)),
                ("signature", risk_counts.get("signature", 0)),
                ("normal", risk_counts.get("normal", 0)),
                ("other", risk_counts.get("other", 0)),
            )
        )
        print(f"Risk breakdown: {summary}")
