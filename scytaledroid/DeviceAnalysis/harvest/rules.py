"""Shared rules and helpers for APK harvest planning."""

from __future__ import annotations

from typing import Iterable, Optional, Sequence, Set

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log

PLAY_STORE_INSTALLER = "com.android.vending"
SYSTEM_PATH_PREFIXES = (
    "/system",
    "/system_ext",
    "/product",
    "/vendor",
    "/apex",
)
FAMILY_PREFIXES = {
    "android": "com.android.",
    "google": "com.google.",
    "motorola": "com.motorola.",
}

_DEFAULT_GOOGLE_ALLOWLIST = {
    "com.google.android.youtube",
    "com.google.android.apps.youtube.music",
    "com.google.android.apps.maps",
    "com.google.android.apps.photos",
    "com.google.android.apps.docs",
    "com.google.android.gm",
    "com.android.chrome",
    "com.google.android.apps.walletnfcrel",
    "com.google.android.apps.messaging",
    "com.google.android.contacts",
}


def _coerce_allowlist(value: object) -> Set[str]:
    if not value:
        return set()
    if isinstance(value, (str, bytes)):
        return {str(value)}
    if isinstance(value, Iterable):
        return {str(item).strip() for item in value if str(item).strip()}
    return set()


def _base_google_allowlist() -> Set[str]:
    config_value = getattr(app_config, "DEVICE_ANALYSIS_GOOGLE_ALLOWLIST", None)
    config_allowlist = _coerce_allowlist(config_value)
    if config_allowlist:
        return config_allowlist
    return set(_DEFAULT_GOOGLE_ALLOWLIST)


def load_google_allowlist(candidates: Optional[Sequence[str]] = None) -> Set[str]:
    """Return Google packages that should bypass the default family exclusion.

    The allow-list is derived from the database when available so analysts can
    adjust policy without redeploying code. If the database query fails, the
    configured/static defaults are returned.
    """

    baseline = set(candidates or _base_google_allowlist())
    if not baseline:
        return set()

    placeholders = ", ".join(["%s"] * len(baseline))
    query = (
        "SELECT package_name FROM android_app_definitions "
        f"WHERE package_name IN ({placeholders})"
    )

    try:
        rows = db_queries.run_sql(query, tuple(sorted(baseline)), fetch="all", dictionary=True)
    except Exception as exc:  # pragma: no cover - defensive logging path
        log.warning(
            f"Failed to load Google allow-list from database: {exc}",
            category="database",
        )
        return baseline

    if not rows:
        return baseline

    discovered = {
        str(row.get("package_name") or "").strip()
        for row in rows
        if row and row.get("package_name")
    }
    discovered.discard("")
    if not discovered:
        return baseline

    # Use discovered packages but keep any explicit configuration extras.
    return discovered | (baseline - discovered)


GOOGLE_ALLOWLIST: Set[str] = load_google_allowlist()


def canonical_filename(package_name: str, version_code: str, artifact: str) -> str:
    """Return deterministic ``package_version__artifact.apk`` filenames."""

    safe_package = package_name.replace(".", "_") or "package"
    safe_version = version_code or "unknown"
    return f"{safe_package}_{safe_version}__{artifact}.apk"


def family(package_name: str) -> Optional[str]:
    """Return the family identifier for the provided package name."""

    for label, prefix in FAMILY_PREFIXES.items():
        if package_name.startswith(prefix):
            return label
    return None


def is_user_path(path: Optional[str]) -> bool:
    """Return ``True`` when the path resides on the user data partition."""

    return bool(path and path.startswith("/data/"))


def is_system_path(path: Optional[str]) -> bool:
    """Return ``True`` for system/vendor/mainline partitions."""

    if not path:
        return False
    return path.startswith(SYSTEM_PATH_PREFIXES)


__all__ = [
    "PLAY_STORE_INSTALLER",
    "SYSTEM_PATH_PREFIXES",
    "GOOGLE_ALLOWLIST",
    "load_google_allowlist",
    "canonical_filename",
    "family",
    "is_user_path",
    "is_system_path",
]

