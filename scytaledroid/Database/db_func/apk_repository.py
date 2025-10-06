"""apk_repository.py - High level helpers for the APK repository tables."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Sequence, Union

from ..db_core import run_sql
from ..db_queries import apk_repository as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log


@dataclass
class ApkRecord:
    """Payload used when ingesting APK metadata into the repository."""

    package_name: str
    app_id: Optional[int] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    is_system: bool = False
    installer: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    signer_fingerprint: Optional[str] = None
    device_serial: Optional[str] = None
    source_path: Optional[str] = None
    local_path: Optional[str] = None
    harvested_at: Optional[Union[datetime, str]] = None
    is_split_member: bool = False
    split_group_id: Optional[int] = None

    def to_parameters(self) -> Dict[str, object]:
        if not self.package_name:
            raise ValueError("package_name is required")
        if not self.sha256:
            raise ValueError("sha256 is required for deduplication")

        harvested_at: Optional[object]
        if isinstance(self.harvested_at, str):
            try:
                harvested_at = datetime.fromisoformat(self.harvested_at)
            except ValueError:
                harvested_at = self.harvested_at
        else:
            harvested_at = self.harvested_at
        return {
            "app_id": self.app_id,
            "package_name": self.package_name,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "is_system": 1 if self.is_system else 0,
            "installer": self.installer,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "signer_fingerprint": self.signer_fingerprint,
            "device_serial": self.device_serial,
            "source_path": self.source_path,
            "local_path": self.local_path,
            "harvested_at": harvested_at,
            "is_split_member": 1 if self.is_split_member else 0,
            "split_group_id": self.split_group_id,
        }


def upsert_apk_record(record: ApkRecord) -> int:
    """Insert or update an APK row and return the apk_id."""
    params = record.to_parameters()
    run_sql(queries.UPSERT_APK, params)
    row = run_sql(queries.SELECT_APK_ID_BY_SHA256, (record.sha256,), fetch="one")
    if not row:
        raise RuntimeError("Failed to resolve apk_id after upsert")
    return int(row[0])


def get_apk_by_sha256(sha256: str) -> Optional[Dict[str, object]]:
    """Return a dictionary of APK metadata for the given sha256."""
    return run_sql(queries.SELECT_APK_BY_SHA256, (sha256,), fetch="one", dictionary=True)


def ensure_split_group(package_name: str) -> int:
    """Get or create a split group id for the given package."""
    row = run_sql(queries.SELECT_SPLIT_GROUP_BY_PACKAGE, (package_name,), fetch="one")
    if row:
        return int(row[0])
    group_id = run_sql(queries.INSERT_SPLIT_GROUP, (package_name,), return_lastrowid=True)
    if group_id:
        return int(group_id)
    row = run_sql(queries.SELECT_SPLIT_GROUP_BY_PACKAGE, (package_name,), fetch="one")
    if not row:
        raise RuntimeError("Failed to create split group")
    return int(row[0])


def mark_split_members(group_id: int, apk_ids: Sequence[int]) -> None:
    """Update the provided apk_ids to belong to the supplied split group."""
    if not apk_ids:
        return
    placeholders = ", ".join(["%s"] * len(apk_ids))
    query = queries.UPDATE_APK_SPLIT_GROUP_TEMPLATE.format(placeholders=placeholders)
    params: List[int] = [group_id]
    params.extend(int(apk_id) for apk_id in apk_ids)
    run_sql(query, tuple(params))


def fetch_split_members(group_id: int) -> List[Dict[str, object]]:
    """Return metadata for all APKs linked to a split group."""
    return run_sql(queries.SELECT_SPLIT_MEMBERS, (group_id,), fetch="all", dictionary=True)


def fetch_duplicate_hashes(limit: int = 100) -> List[Dict[str, object]]:
    """Return a list of duplicate sha256 hashes for auditing purposes."""
    return run_sql(queries.SELECT_DUPLICATE_HASHES, (limit,), fetch="all", dictionary=True)


def ensure_app_definition(
    package_name: str,
    app_name: Optional[str] = None,
    *,
    category_name: Optional[str] = None,
    profile_id: Optional[str] = None,
    profile_name: Optional[str] = None,
) -> int:
    """Upsert a canonical app definition row and return app_id."""
    cleaned_package = package_name.strip().lower()
    if not cleaned_package:
        raise ValueError("package_name is required")

    label: Optional[str]
    if app_name and app_name.strip():
        candidate = app_name.strip()
        if candidate.lower() == cleaned_package.lower():
            label = None
        else:
            label = candidate
    else:
        label = None

    run_sql(queries.UPSERT_APP_DEFINITION, (cleaned_package, label))
    row = run_sql(queries.SELECT_APP_ID_BY_PACKAGE, (cleaned_package,), fetch="one")
    if not row:
        raise RuntimeError(f"Failed to resolve app_id for package {package_name}")
    app_id = int(row[0])

    update_fields: List[str] = []
    update_params: List[object] = []

    column_flags = _get_definition_profile_columns()
    if category_name and category_name.strip():
        category_id = get_category_id(category_name.strip())
        update_fields.append("category_id = %s")
        update_params.append(category_id)

    if profile_id and str(profile_id).strip():
        if column_flags["profile_id"]:
            update_fields.append("profile_id = %s")
            update_params.append(str(profile_id).strip())
        else:
            _warn_missing_profile_columns()

    if profile_name and profile_name.strip():
        if column_flags["profile_name"]:
            update_fields.append("profile_name = %s")
            update_params.append(profile_name.strip())
        else:
            _warn_missing_profile_columns()

    if update_fields:
        set_clause = ", ".join(update_fields + ["updated_at = CURRENT_TIMESTAMP"])
        update_params.append(cleaned_package)
        run_sql(
            f"""UPDATE android_app_definitions
            SET {set_clause}
            WHERE package_name = %s""",
            tuple(update_params),
        )

    return app_id


@lru_cache(maxsize=1)
def _get_definition_profile_columns() -> Dict[str, bool]:
    """Return availability flags for profile columns on android_app_definitions."""

    try:
        rows = run_sql(
            """
            SELECT COLUMN_NAME
            FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = 'android_app_definitions'
            """,
            fetch="all",
            dictionary=True,
        ) or []
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed to inspect android_app_definitions columns: {exc}",
            category="database",
        )
        return {"profile_id": False, "profile_name": False}

    normalised = {
        str(entry.get("COLUMN_NAME")).lower()
        for entry in rows
        if isinstance(entry, dict) and entry.get("COLUMN_NAME")
    }
    return {
        "profile_id": "profile_id" in normalised,
        "profile_name": "profile_name" in normalised,
    }


_PROFILE_WARNING_EMITTED = False


def _warn_missing_profile_columns() -> None:
    """Log a single actionable warning when profile columns are missing."""

    global _PROFILE_WARNING_EMITTED
    if _PROFILE_WARNING_EMITTED:
        return

    _PROFILE_WARNING_EMITTED = True
    log.warning(
        "Profile metadata detected but android_app_definitions lacks profile_id/profile_name columns."
        " Run the database migration to add them.",
        category="database",
    )


def get_category_id(category_name: str) -> int:
    """Fetch or create a category and return its id."""
    row = run_sql(queries.SELECT_CATEGORY_ID, (category_name,), fetch="one")
    if row:
        return int(row[0])
    category_id = run_sql(queries.INSERT_CATEGORY, (category_name,), return_lastrowid=True)
    if category_id:
        return int(category_id)
    row = run_sql(queries.SELECT_CATEGORY_ID, (category_name,), fetch="one")
    if not row:
        raise RuntimeError("Failed to create category")
    return int(row[0])


def list_categories() -> List[Dict[str, object]]:
    """Return all available categories sorted alphabetically."""
    return run_sql(queries.LIST_CATEGORIES, fetch="all", dictionary=True)


def assign_split_members(package_name: str, apk_ids: Iterable[int]) -> int:
    """Convenience helper to create a split group and assign members."""
    apk_ids_list = [int(apk_id) for apk_id in apk_ids]
    if not apk_ids_list:
        raise ValueError("assign_split_members requires at least one apk_id")
    group_id = ensure_split_group(package_name)
    mark_split_members(group_id, apk_ids_list)
    return group_id


__all__ = [
    "ApkRecord",
    "upsert_apk_record",
    "get_apk_by_sha256",
    "ensure_split_group",
    "mark_split_members",
    "fetch_split_members",
    "fetch_duplicate_hashes",
    "get_category_id",
    "list_categories",
    "assign_split_members",
    "ensure_app_definition",
]
