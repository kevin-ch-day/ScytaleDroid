"""Category resolution helpers for static analysis scans."""

from __future__ import annotations

import json
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.package_profiles import lookup_profile

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

_GENERIC_CATEGORY_LABELS = {
    "",
    "user",
    "system",
    "uncategorized",
    "unknown",
    "other",
    "misc",
}

_PROFILE_CATEGORY_MAP: Mapping[str, tuple[str, str, str]] = {
    "BROWSER": ("Browser", "high", "apps.profile_key=BROWSER"),
    "NEWS": ("News", "high", "apps.profile_key=NEWS"),
    "MEDIA": ("Media & streaming", "high", "apps.profile_key=MEDIA"),
    "PRODUCTIVITY": ("Productivity", "high", "apps.profile_key=PRODUCTIVITY"),
    "MESSAGING": ("Messaging", "high", "apps.profile_key=MESSAGING"),
    "SHOPPING": ("Shopping", "high", "apps.profile_key=SHOPPING"),
    "HEALTH": ("Health & fitness", "high", "apps.profile_key=HEALTH"),
}
_SOCIAL_PUBLISHERS = {"META", "SNAP", "REDDIT", "X_CORP", "PINTEREST", "BYTEDANCE", "TIKTOK"}
_MESSAGING_PUBLISHERS = {"TELEGRAM", "DISCORD", "SIGNAL"}
_NEWS_PUBLISHERS = {"BBC", "CNN", "GUARDIAN", "ASSOCIATED_PRESS", "NEWSMAX", "FOX"}
_MEDIA_PUBLISHERS = {"DISNEY", "NETFLIX", "SPOTIFY", "CRUNCHYROLL"}
_FINANCE_TOKENS = (
    "bank",
    "chase",
    "citi",
    "capital one",
    "venmo",
    "coinbase",
    "kalshi",
    "go2bank",
    "schwab",
    "robinhood",
)
_SHOPPING_TOKENS = (
    "amazon shopping",
    "walmart",
    "ebay",
    "temu",
    "best buy",
    "bath & body works",
    "bathandbody",
    "shopping",
    "target",
)
_MEDIA_TOKENS = (
    "netflix",
    "disney+",
    "prime video",
    "amazon music",
    "youtube",
    "spotify",
    "crunchyroll",
    "music",
    "video",
)
_NEWS_TOKENS = ("news", "cnn", "bbc", "guardian", "newsmax", "fox nation")
_TRAVEL_TOKENS = ("airbnb", "expedia", "best western", "travel", "booking")
_HEALTH_TOKENS = ("fitness", "health", "fitbit")
_GAME_TOKENS = ("roblox", "game", "play games")
_PRODUCTIVITY_TOKENS = ("dropbox", "acrobat", "gmail", "docs", "sheets", "copilot", "office")


@dataclass(frozen=True)
class CategoryResolution:
    category: str
    source: str
    confidence: str
    reason: str
    needs_review: bool = False


def _repo_seed_map_path() -> Path:
    return Path(__file__).with_name("category_seed_map.json")


def _local_category_map_path() -> Path:
    return Path(app_config.DATA_DIR) / "static_analysis" / "category_map.json"


@lru_cache(maxsize=1)
def _load_custom_category_map() -> Mapping[str, str]:
    path = _local_category_map_path()
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


@lru_cache(maxsize=1)
def _load_local_override_map() -> Mapping[str, str]:
    path = _local_category_map_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    mapping: MutableMapping[str, str] = {}
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            cleaned_key = key.strip()
            cleaned_value = value.strip()
            if cleaned_key and cleaned_value:
                mapping[cleaned_key] = cleaned_value
    return mapping


@lru_cache(maxsize=1)
def _load_repo_seed_payload() -> Mapping[str, object]:
    path = _repo_seed_map_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def _is_generic_category(value: object) -> bool:
    text = str(value or "").strip().lower()
    return text in _GENERIC_CATEGORY_LABELS


def _normalized_text(value: object) -> str:
    return str(value or "").strip()


def _seed_resolution(package_name: str) -> CategoryResolution | None:
    payload = _load_repo_seed_payload()
    exact = payload.get("exact")
    if isinstance(exact, Mapping):
        row = exact.get(package_name)
        if isinstance(row, Mapping):
            category = _normalized_text(row.get("category"))
            if category:
                return CategoryResolution(
                    category=category,
                    source=_normalized_text(row.get("source")) or "curated_seed_exact",
                    confidence=_normalized_text(row.get("confidence")) or "high",
                    reason=_normalized_text(row.get("reason")) or f"repo seed exact match for {package_name}",
                    needs_review=bool(row.get("needs_review")),
                )
    prefixes = payload.get("prefix")
    if isinstance(prefixes, Mapping):
        for prefix, row in prefixes.items():
            if not isinstance(prefix, str) or not package_name.startswith(prefix):
                continue
            if not isinstance(row, Mapping):
                continue
            category = _normalized_text(row.get("category"))
            if category:
                return CategoryResolution(
                    category=category,
                    source=_normalized_text(row.get("source")) or "curated_seed_prefix",
                    confidence=_normalized_text(row.get("confidence")) or "high",
                    reason=_normalized_text(row.get("reason")) or f"repo seed prefix match: {prefix}",
                    needs_review=bool(row.get("needs_review")),
                )
    return None


def _local_override_resolution(package_name: str) -> CategoryResolution | None:
    mapping = _load_local_override_map()
    if package_name in mapping:
        return CategoryResolution(
            category=str(mapping[package_name]).strip(),
            source="local_category_override",
            confidence="high",
            reason=f"data/static_analysis/category_map.json exact match for {package_name}",
        )
    for prefix, label in mapping.items():
        if package_name.startswith(prefix):
            return CategoryResolution(
                category=str(label).strip(),
                source="local_category_override",
                confidence="high",
                reason=f"data/static_analysis/category_map.json prefix match: {prefix}",
            )
    return None


def _role_classification(
    package_name: str,
    metadata: Mapping[str, object],
) -> CategoryResolution | None:
    profile_key = _normalized_text(metadata.get("profile_key")).upper()
    publisher_key = _normalized_text(metadata.get("publisher_key")).upper()
    owner_role = _normalized_text(metadata.get("owner_role")).lower()
    source = _normalized_text(metadata.get("source")).lower()

    if profile_key == "SYSTEM_CORE" or owner_role == "system" or source == "system":
        if publisher_key in {"GOOGLE", "ANDROID_AOSP"} or package_name.startswith(("android.", "com.android.", "com.google.android.")):
            return CategoryResolution(
                category="Platform / system",
                source="role_classification",
                confidence="high",
                reason="system/platform metadata and package/publisher indicators",
            )
        if publisher_key in {"MOTOROLA", "QUALCOMM", "GLANCE"} or package_name.startswith(("com.motorola.", "com.qualcomm.", "com.qti.")):
            return CategoryResolution(
                category="OEM / system",
                source="role_classification",
                confidence="high",
                reason="system-core package with OEM publisher/package indicators",
            )
        if publisher_key in {"VERIZON", "ATT", "TMOBILE"} or package_name.startswith(("com.vzw.", "com.att.", "com.tmobile.")):
            return CategoryResolution(
                category="Carrier / vendor",
                source="role_classification",
                confidence="high",
                reason="system/carrier package with carrier publisher/package indicators",
            )
        return CategoryResolution(
            category="Platform / system",
            source="role_classification",
            confidence="medium",
            reason="system-core metadata without a stronger OEM/carrier distinction",
            needs_review=True,
        )

    if profile_key == "GOOGLE_USER" and publisher_key in {"GOOGLE", "ANDROID_AOSP"}:
        return CategoryResolution(
            category="Google app",
            source="role_classification",
            confidence="medium",
            reason="google-user profile and Google/AOSP publisher metadata",
        )
    return None


def _profile_resolution(
    package_name: str,
    metadata: Mapping[str, object],
) -> CategoryResolution | None:
    profile_key = _normalized_text(metadata.get("profile_key")).upper()
    if profile_key in _PROFILE_CATEGORY_MAP:
        category, confidence, reason = _PROFILE_CATEGORY_MAP[profile_key]
        return CategoryResolution(
            category=category,
            source="profile_key",
            confidence=confidence,
            reason=reason,
        )
    package_profile = lookup_profile(package_name)
    if package_profile is None:
        return None
    mapped = {
        "SOCIAL": "Social media",
        "MESSAGING": "Messaging",
        "SHOPPING": "Shopping",
    }.get(package_profile.id)
    if not mapped:
        return None
    return CategoryResolution(
        category=mapped,
        source="package_profile",
        confidence="medium",
        reason=f"package_profiles match: {package_profile.id}",
    )


def _publisher_resolution(
    metadata: Mapping[str, object],
) -> CategoryResolution | None:
    publisher_key = _normalized_text(metadata.get("publisher_key")).upper()
    if publisher_key in _SOCIAL_PUBLISHERS:
        return CategoryResolution("Social media", "publisher_key", "medium", f"publisher_key={publisher_key}")
    if publisher_key in _MESSAGING_PUBLISHERS:
        return CategoryResolution("Messaging", "publisher_key", "medium", f"publisher_key={publisher_key}")
    if publisher_key in _NEWS_PUBLISHERS:
        return CategoryResolution("News", "publisher_key", "medium", f"publisher_key={publisher_key}")
    if publisher_key in _MEDIA_PUBLISHERS:
        return CategoryResolution("Media & streaming", "publisher_key", "medium", f"publisher_key={publisher_key}")
    return None


def _contains_any(text: str, tokens: Sequence[str]) -> str | None:
    haystack = text.lower()
    for token in tokens:
        if token.lower() in haystack:
            return token
    return None


def _heuristic_resolution(
    package_name: str,
    metadata: Mapping[str, object],
) -> CategoryResolution | None:
    display_name = _normalized_text(metadata.get("display_name") or metadata.get("app_label"))
    combined = " ".join(filter(None, [package_name.replace(".", " "), display_name])).lower()

    if package_name.startswith(("com.google.android.apps.messaging", "org.thoughtcrime.securesms")):
        return CategoryResolution("Messaging", "heuristic_exact", "medium", f"exact package heuristic: {package_name}")

    token = _contains_any(combined, _FINANCE_TOKENS)
    if token:
        return CategoryResolution("Finance", "heuristic_label", "medium", f"matched finance token: {token}")
    token = _contains_any(combined, _SHOPPING_TOKENS)
    if token:
        return CategoryResolution("Shopping", "heuristic_label", "medium", f"matched shopping token: {token}")
    token = _contains_any(combined, _MEDIA_TOKENS)
    if token:
        return CategoryResolution("Media & streaming", "heuristic_label", "medium", f"matched media token: {token}")
    token = _contains_any(combined, _NEWS_TOKENS)
    if token:
        return CategoryResolution("News", "heuristic_label", "medium", f"matched news token: {token}")
    token = _contains_any(combined, _TRAVEL_TOKENS)
    if token:
        return CategoryResolution("Travel", "heuristic_label", "medium", f"matched travel token: {token}")
    token = _contains_any(combined, _HEALTH_TOKENS)
    if token:
        return CategoryResolution("Health & fitness", "heuristic_label", "medium", f"matched health token: {token}")
    token = _contains_any(combined, _GAME_TOKENS)
    if token:
        return CategoryResolution("Games", "heuristic_label", "medium", f"matched game token: {token}")
    token = _contains_any(combined, _PRODUCTIVITY_TOKENS)
    if token:
        return CategoryResolution("Productivity", "heuristic_label", "medium", f"matched productivity token: {token}")
    return None


def resolve_category_with_provenance(
    package_name: str,
    metadata: Mapping[str, object],
) -> CategoryResolution:
    manual_category = metadata.get("manual_category")
    if isinstance(manual_category, str) and manual_category.strip():
        return CategoryResolution(
            category=manual_category.strip(),
            source="manual_metadata",
            confidence="high",
            reason="manual_category metadata provided by caller",
        )

    # Explicit non-generic metadata category can win if supplied.
    for key in ("category", "category_name"):
        candidate = metadata.get(key)
        if isinstance(candidate, str) and candidate.strip() and not _is_generic_category(candidate):
            return CategoryResolution(
                category=candidate.strip(),
                source=_normalized_text(metadata.get("category_source")) or "metadata_category",
                confidence="high" if not bool(metadata.get("inferred_category")) else "medium",
                reason=f"{key} supplied by metadata",
            )

    for resolver in (
        _local_override_resolution,
        _seed_resolution,
    ):
        resolved = resolver(package_name)
        if resolved is not None:
            return resolved

    role = _role_classification(package_name, metadata)
    if role is not None:
        return role

    profile = _profile_resolution(package_name, metadata)
    if profile is not None:
        return profile

    publisher = _publisher_resolution(metadata)
    if publisher is not None:
        return publisher

    heuristic = _heuristic_resolution(package_name, metadata)
    if heuristic is not None:
        return heuristic

    if isinstance(metadata.get("review_needed"), bool) and bool(metadata.get("review_needed")):
        return CategoryResolution(
            category="Unknown / review",
            source="review_fallback",
            confidence="low",
            reason="inventory metadata already marked the package for review",
            needs_review=True,
        )

    return CategoryResolution(
        category="Unknown / review",
        source="unresolved",
        confidence="low",
        reason="no curated, profile, role, publisher, or conservative heuristic category matched",
        needs_review=True,
    )


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


__all__ = ["CategoryResolution", "resolve_category", "resolve_category_with_provenance"]
