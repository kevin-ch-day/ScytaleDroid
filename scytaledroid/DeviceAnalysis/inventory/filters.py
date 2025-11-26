"""Reusable inventory filters for scoped syncs."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.inventory.package_collection import PackageRow


def user_only(row: PackageRow) -> bool:
    """Return True if the package looks like a user-installed app."""
    return (row.partition or "").lower().startswith("/data")


def social(row: PackageRow) -> bool:
    return (row.profile_name or "").lower() in {"social", "messaging"}


def finance(row: PackageRow) -> bool:
    return (row.profile_name or "").lower() in {"finance", "shopping"}


__all__ = ["user_only", "social", "finance"]
