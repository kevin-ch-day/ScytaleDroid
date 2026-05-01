"""Diagnostics helpers to compute inventory metrics for summaries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from scytaledroid.DeviceAnalysis.inventory.progress import format_inventory_elapsed


@dataclass
class InventoryMetrics:
    total_packages: int
    split_apk_packages: int
    user_scope_candidates: int
    by_install_source: Mapping[str, int]
    by_role: Mapping[str, int]
    by_partition: Mapping[str, int]
    delta_new: int
    delta_removed: int
    delta_updated: int
    scan_duration: str


def compute_inventory_metrics(result) -> InventoryMetrics:
    """
    Compute summary metrics from an existing InventoryResult-like object
    (current runner output). This keeps us compatible while we migrate to
    richer domain models.
    """
    rows = getattr(result, "rows", None) or []
    total = len(rows)
    split_apk_packages = sum(1 for entry in rows if int(entry.get("split_count") or 1) > 1)

    def _owner_role(entry: Mapping[str, object]) -> str:
        value = entry.get("owner_role")
        if value not in {None, ""}:
            return str(value)
        primary_path = str(entry.get("primary_path") or "")
        if primary_path.startswith("/data/"):
            return "User"
        if primary_path.startswith("/product/"):
            return "OEM"
        if primary_path.startswith("/system/") or primary_path.startswith("/system_ext/"):
            return "System"
        if primary_path.startswith("/apex/"):
            return "Mainline"
        if primary_path.startswith("/vendor/"):
            return "Vendor"
        if primary_path:
            return "Other"
        return "Unknown"

    by_role: dict[str, int] = {}
    for entry in rows:
        role = _owner_role(entry)
        by_role[role] = by_role.get(role, 0) + 1

    user_entries = [entry for entry in rows if _owner_role(entry) == "User"]
    user_scope_candidates = len(user_entries)

    by_source: dict[str, int] = {}
    for entry in user_entries:
        src = str(entry.get("source") or "Unknown")
        by_source[src] = by_source.get(src, 0) + 1

    by_partition: dict[str, int] = {}
    for entry in rows:
        primary_path = str(entry.get("primary_path") or "")
        if primary_path.startswith("/data/"):
            label = "Data (/data)"
        elif primary_path.startswith("/product/"):
            label = "Product (/product)"
        elif primary_path.startswith("/system/") or primary_path.startswith("/system_ext/"):
            label = "System (/system, /system_ext)"
        elif primary_path.startswith("/apex/"):
            label = "Apex (/apex)"
        elif primary_path.startswith("/vendor/"):
            label = "Vendor (/vendor)"
        elif primary_path:
            label = "Other"
        else:
            label = "Unknown"
        by_partition[label] = by_partition.get(label, 0) + 1

    delta = getattr(result, "delta", None)
    delta_new = int(getattr(delta, "new_count", 0) or 0) if delta else 0
    delta_removed = int(getattr(delta, "removed_count", 0) or 0) if delta else 0
    delta_updated = int(getattr(delta, "updated_count", 0) or 0) if delta else 0

    scan_duration = format_inventory_elapsed(getattr(result, "elapsed_seconds", None), absent="--")

    return InventoryMetrics(
        total_packages=total,
        split_apk_packages=split_apk_packages,
        user_scope_candidates=user_scope_candidates,
        by_install_source=by_source,
        by_role=by_role,
        by_partition=by_partition,
        delta_new=delta_new,
        delta_removed=delta_removed,
        delta_updated=delta_updated,
        scan_duration=scan_duration,
    )