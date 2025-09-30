"""apk_repository.py - High level helpers for the APK repository tables."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from ..db_core import run_sql
from ..db_queries import apk_repository as queries


@dataclass
class ApkRecord:
    """Payload used when ingesting APK metadata into the repository."""

    package_name: str
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
    is_split_member: bool = False
    split_group_id: Optional[int] = None

    def to_parameters(self) -> Dict[str, object]:
        if not self.package_name:
            raise ValueError("package_name is required")
        if not self.sha256:
            raise ValueError("sha256 is required for deduplication")
        return {
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


def ensure_app_definition(package_name: str, app_name: Optional[str] = None) -> int:
    """Upsert a canonical app definition row and return app_id."""
    normalized = package_name.lower().strip()
    run_sql(queries.UPSERT_APP_DEFINITION, (normalized, app_name))
    row = run_sql(queries.SELECT_APP_ID_BY_PACKAGE, (normalized,), fetch="one")
    if not row:
        raise RuntimeError(f"Failed to resolve app_id for package {package_name}")
    return int(row[0])


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
