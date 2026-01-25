"""Centralized legacy-table guard for startup warnings."""

from __future__ import annotations

from typing import Iterable, Sequence

from ..db_core import run_sql

_LEGACY_TABLES: Sequence[str] = (
    "android_detected_permissions",
    "android_framework_permissions",
    "android_unknown_permissions",
    "android_vendor_permissions",
    "android_perm_map",
    "android_perm_override",
    "aosp_permission_baseline",
    "android_publisher_prefix_rules",
)


def _existing_tables(names: Iterable[str]) -> list[str]:
    found: list[str] = []
    for name in names:
        row = run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
            (name,),
            fetch="one",
        )
        if row and int(row[0]) > 0:
            found.append(name)
    return found


def legacy_table_warnings() -> list[str]:
    """Return a list of legacy tables that still exist."""
    try:
        return _existing_tables(_LEGACY_TABLES)
    except Exception:
        return []


__all__ = ["legacy_table_warnings"]
