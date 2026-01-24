"""Normalization helpers for inventory entries (UI-free)."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .. import package_profiles


def compose_inventory_entry(
    package_name: str,
    paths: List[str],
    metadata: Dict[str, Optional[str]],
    canonical: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    primary_path = paths[0] if paths else ""
    fallback_category, partition = _derive_category(primary_path)
    installer = _normalise_installer(metadata.get("installer"))
    review_needed = canonical is None

    category_id = canonical.get("category_id") if canonical else None
    category_name = canonical.get("category_name") if canonical else None
    category_source = "apps_join" if category_name else "inferred_partition"
    heuristic_category = False
    if not category_name:
        category_name = fallback_category
        heuristic_category = True

    profile_key = canonical.get("profile_key") if canonical else None
    profile_name = canonical.get("profile_name") if canonical else None
    profile_source = "apps_join" if profile_key or profile_name else "fallback"
    publisher_key = canonical.get("publisher_key") if canonical else None
    publisher_name = canonical.get("publisher_name") if canonical else None
    publisher_source = "apps_join" if publisher_key or publisher_name else "fallback"
    heuristic_profile = False
    if not profile_key and not profile_name:
        profile = package_profiles.lookup_profile(package_name)
        profile_key = profile.id.upper() if profile else None
        profile_name = profile.name if profile else None
        heuristic_profile = bool(profile_key or profile_name)
        if heuristic_profile:
            profile_source = "inferred_partition"

    if not profile_key:
        profile_key = "UNCLASSIFIED"
        profile_name = profile_name or "Unclassified"
        profile_source = "fallback"

    if not publisher_key:
        publisher_key = "VENDOR_MISC"
        publisher_name = publisher_name or "Vendor Misc"
        publisher_source = "fallback"

    if heuristic_category or heuristic_profile:
        review_needed = True

    source_category = category_name if category_name in _CATEGORY_ORDER else fallback_category
    source = _derive_source(str(source_category or fallback_category), installer)

    role = fallback_category  # partition-derived owner role (User/OEM/System/Mainline/Vendor/Other/Unknown)

    canonical_label = canonical.get("app_name") if canonical else None
    metadata_label = metadata.get("app_label")
    package_lower = package_name.lower()
    canonical_clean = canonical_label.strip() if isinstance(canonical_label, str) else None
    metadata_clean = metadata_label.strip() if isinstance(metadata_label, str) else None
    if canonical_clean and canonical_clean.lower() != package_lower:
        app_label = canonical_clean
    elif metadata_clean:
        app_label = metadata_clean
    elif canonical_clean:
        app_label = canonical_clean
    else:
        app_label = package_name
    version_name = metadata.get("version_name")
    version_code = metadata.get("version_code")

    split_count = len(paths)
    apk_dirs = sorted({path.rsplit("/", 1)[0] for path in paths if "/" in path})

    entry: Dict[str, object] = {
        "package_name": package_name,
        "app_label": app_label,
        "version_name": version_name,
        "version_code": version_code,
        "installer": installer,
        "first_install": metadata.get("first_install"),
        "last_update": metadata.get("last_update"),
        "primary_path": primary_path,
        "category": category_name,
        "category_name": category_name,
        "category_id": category_id,
        "partition": partition,
        "source": source,
        "profile_key": profile_key,
        "profile_id": profile_key,
        "profile_name": profile_name,
        "publisher_key": publisher_key,
        "publisher_name": publisher_name,
        "category_source": category_source,
        "profile_source": profile_source,
        "publisher_source": publisher_source,
        "split_flag": "Yes" if split_count > 1 else "No",
        "apk_paths": paths,
        "apk_dirs": apk_dirs,
        "review_needed": review_needed,
        "inferred_category": heuristic_category,
        "inferred_profile": heuristic_profile,
        # owner/role derived from partition; kept separate from semantic category_name
        "owner_role": role,
    }

    entry["split_count"] = split_count  # type: ignore[index]

    return entry


_CATEGORY_ORDER = {
    "User": 0,
    "OEM": 1,
    "System": 2,
    "Mainline": 3,
    "Vendor": 4,
    "Other": 5,
    "Unknown": 6,
}


def _derive_category(primary_path: str) -> Tuple[str, str]:
    if primary_path.startswith("/data/"):
        return "User", "Data (/data)"
    if primary_path.startswith("/product/"):
        return "OEM", "Product (/product)"
    if primary_path.startswith("/system_ext/") or primary_path.startswith("/system/"):
        return "System", "System (/system, /system_ext)"
    if primary_path.startswith("/apex/"):
        return "Mainline", "Apex (/apex)"
    if primary_path.startswith("/vendor/"):
        return "Vendor", "Vendor (/vendor)"
    if primary_path:
        return "Other", "Other"
    return "Unknown", "Unknown"


def _derive_source(category: str, installer: Optional[str]) -> str:
    if category == "User":
        if installer == "com.android.vending":
            return "Play Store"
        if installer and installer not in {"Unknown", "unset"}:
            return installer
        return "Sideload"
    if category == "Mainline":
        return "Google Mainline"
    if category == "OEM":
        return "OEM/Carrier"
    if category == "Vendor":
        return "Vendor"
    if category == "System":
        return "System"
    return category


def _normalise_installer(installer: Optional[str]) -> Optional[str]:
    if not installer or installer.lower() in {"null", "none", ""}:
        return None
    return installer


def split_count(entry: Dict[str, object]) -> int:
    value = entry.get("split_count")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            if value.lower() in {"yes", "true"}:
                paths = entry.get("apk_paths")
                if isinstance(paths, list) and paths:
                    return len(paths)
                return 2
    return 1
