"""Reusable inventory filters for scoped syncs."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.inventory.package_collection import PackageRow


def user_only(row: PackageRow) -> bool:
    """Return True if the package looks like a user-installed app."""
    return (row.partition or "").lower().startswith("/data")


def social(row: PackageRow) -> bool:
    return (row.get("profile_key") or "").upper() in {"SOCIAL", "MESSAGING"}


def finance(row: PackageRow) -> bool:
    return (row.get("profile_key") or "").upper() in {"SHOPPING", "AMAZON_USER"}


__all__ = ["user_only", "social", "finance"]
