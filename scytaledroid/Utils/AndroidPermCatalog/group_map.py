from __future__ import annotations

from typing import Dict, Optional
import os
from pathlib import Path


_AOSP_MANIFEST_URLS = (
    # AOSP mirror mainline manifest
    "https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/master/core/res/AndroidManifest.xml",
    # Android platform frameworks (alternate mirror)
    "https://raw.githubusercontent.com/android/platform_frameworks_base/master/core/res/AndroidManifest.xml",
)


def _fetch(url: str, timeout: int = 20) -> Optional[str]:
    try:
        import requests  # type: ignore

        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception:
        try:
            from urllib.request import urlopen

            with urlopen(url, timeout=timeout) as resp:  # nosec - fixed URL list
                return resp.read().decode("utf-8", errors="ignore")
        except Exception:
            return None


def fetch_aosp_manifest() -> Optional[str]:
    for url in _AOSP_MANIFEST_URLS:
        text = _fetch(url)
        if text:
            return text
    return None


def fetch_sdk_manifest() -> Optional[str]:
    """Try to locate a framework AndroidManifest.xml under the local SDK.

    Searches ANDROID_SDK_ROOT or ANDROID_HOME platforms/*/data/res/AndroidManifest.xml,
    preferring the highest API level available.
    """
    root = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if not root:
        return None
    base = Path(root) / "platforms"
    if not base.exists():
        return None
    candidates: list[Path] = []
    for platform_dir in base.glob("android-*"):
        manifest = platform_dir / "data" / "res" / "AndroidManifest.xml"
        if manifest.exists():
            candidates.append(manifest)
    if not candidates:
        return None
    def _api_key(p: Path) -> int:
        try:
            return int(p.parent.name.split("-", 1)[1])
        except Exception:
            return -1
    best = sorted(candidates, key=_api_key, reverse=True)[0]
    try:
        return best.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None


def parse_groups(manifest_xml: str) -> Dict[str, str]:
    """Return a mapping of permission constant -> group short name.

    Parses AndroidManifest.xml from the AOSP frameworks base and extracts
    android:permissionGroup attributes from <permission> elements.
    """

    from xml.etree import ElementTree as ET

    try:
        root = ET.fromstring(manifest_xml)
    except Exception:
        return {}

    # Namespaces used by Android manifests
    ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

    groups: Dict[str, str] = {}
    for perm in root.findall(".//permission"):
        name = perm.get(ANDROID_NS + "name")
        group = perm.get(ANDROID_NS + "permissionGroup")
        if not name or not group:
            continue
        # Group values are typically like "android.permission-group.LOCATION"
        short = group.split(".")[-1] if "." in group else group
        groups[name] = short
    return groups


def attach_groups(items: list) -> int:
    """Attempt to attach group to catalog items using AOSP manifest.

    Returns number of items updated.
    """

    # Prefer local SDK manifest for completeness; fall back to AOSP online.
    manifest = fetch_sdk_manifest() or fetch_aosp_manifest()
    if not manifest:
        return 0
    mapping = parse_groups(manifest)
    if not mapping:
        return 0

    updated = 0
    for entry in items:
        try:
            const = entry.name  # PermissionMeta
        except AttributeError:
            const = entry.get("name")
        group = mapping.get(const)
        if group and getattr(entry, "group", None) != group:
            try:
                # Dataclass-like
                object.__setattr__(entry, "group", group)
            except Exception:
                # dict-like
                entry["group"] = group
            updated += 1
    return updated


__all__ = ["attach_groups", "fetch_aosp_manifest", "parse_groups"]
