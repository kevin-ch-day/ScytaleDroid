"""Formatting helpers for inventory status used by the device menu."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.services import device_service


def format_inventory_status(serial: str | None) -> str:
    if not serial:
        return "connect device"
    status = device_service.fetch_inventory_metadata(serial)
    if not status:
        return "not yet run"
    if status.last_run_ts is None:
        return "not yet run"
    label = status.status_label.lower()
    mode = str(getattr(status, "collection_mode", "") or "").strip().lower()
    if mode == "bulk":
        label = f"{label} harvest-ready"
    elif mode == "baseline":
        label = f"{label} baseline-full"
    elif mode == "user_only":
        label = f"{label} profile-only"
    age = status.age_display
    text = f"{label} {age} ago" if age and age != "unknown" else label
    if status.is_stale:
        text = f"{text} (stale)"
    return text


def format_pull_hint(serial: str | None) -> str:
    if not serial:
        return "requires device"
    status = device_service.fetch_inventory_metadata(serial)
    if not status or status.last_run_ts is None:
        return "needs inventory sync"
    count = status.package_count
    mode = str(getattr(status, "collection_mode", "") or "").strip().lower()
    mode_suffix = ""
    if mode == "bulk":
        mode_suffix = ", harvest-ready"
    elif mode == "baseline":
        mode_suffix = ", baseline-full"
    elif mode == "user_only":
        mode_suffix = ", profile-only"
    prefix = "inventory stale" if status.is_stale else "inventory ready"
    if isinstance(count, int):
        return f"{prefix} ({count} packages{mode_suffix})"
    return prefix
