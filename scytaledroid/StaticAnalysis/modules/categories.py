"""Category resolution helpers for static analysis scans."""

from __future__ import annotations

import json
from collections.abc import Mapping, MutableMapping
from functools import lru_cache
from pathlib import Path

from scytaledroid.Config import app_config

_DEFAULT_CATEGORY_MAP: Mapping[str, str] = {
    # Social / Communication
    "com.facebook.katana": "Social media",
    "com.facebook.orca": "Social media",
    "com.instagram.android": "Social media",
    "com.twitter.android": "Social media",
    "com.reddit.frontpage": "Social media",
    "com.snapchat.android": "Social media",
    "com.discord": "Social media",
    "com.telegram.messenger": "Communication",
    "org.telegram.messenger": "Communication",
    "com.whatsapp": "Communication",
    "com.google.android.apps.messaging": "Communication",
    # Google / fitness
    "com.google.android.apps.fitness": "Health & fitness",
    "com.google.android.gm": "Productivity",
    "com.google.android.apps.nbu.files": "Productivity",
    # Shopping
    "com.target.ui": "Shopping",
    # Entertainment
    "com.zhiliaoapp.musically": "Entertainment",
    "com.pinterest": "Social media",
}


@lru_cache(maxsize=1)
def _load_custom_category_map() -> Mapping[str, str]:
    path = Path(app_config.DATA_DIR) / "static_analysis" / "category_map.json"
    if not path.exists():
        return _DEFAULT_CATEGORY_MAP
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return _DEFAULT_CATEGORY_MAP
    mapping: MutableMapping[str, str] = {}
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            cleaned_key = key.strip()
            cleaned_value = value.strip()
            if cleaned_key and cleaned_value:
                mapping[cleaned_key] = cleaned_value
    mapping.update(_DEFAULT_CATEGORY_MAP)
    return mapping


def resolve_category(package_name: str, metadata: Mapping[str, object]) -> str:
    """Return the category label for *package_name* using metadata and overrides."""

    meta_category = metadata.get("category")
    if isinstance(meta_category, str) and meta_category.strip():
        return meta_category.strip()

    mapping = _load_custom_category_map()
    if package_name in mapping:
        return mapping[package_name]

    # Attempt prefix match (e.g. com.facebook.)
    for prefix, label in mapping.items():
        if package_name.startswith(prefix):
            return label

    return "Uncategorized"


__all__ = ["resolve_category"]