"""High-level database functions exposed to application layers."""

from .apk_repository import (
    ApkRecord,
    upsert_apk_record,
    get_apk_by_sha256,
    ensure_split_group,
    mark_split_members,
    fetch_split_members,
    fetch_duplicate_hashes,
    get_category_id,
    list_categories,
    assign_split_members,
    ensure_app_definition,
)

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
