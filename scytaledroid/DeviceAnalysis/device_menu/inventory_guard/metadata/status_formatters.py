"""Formatting helpers for inventory status used by the device menu."""

from __future__ import annotations

from typing import Optional

from scytaledroid.DeviceAnalysis.services import device_service
from scytaledroid.DeviceAnalysis import inventory as inventory_module


def format_inventory_status(serial: Optional[str]) -> str:
    if not serial:
        return "connect device"
    status = device_service.fetch_inventory_metadata(serial)
    if not status:
        return "not yet run"
    if status.last_run_ts is None:
        return "not yet run"
    label = status.status_label.lower()
    age = status.age_display
    text = f"{label} {age} ago" if age and age != "unknown" else label
    if status.is_stale:
        text = f"{text} (stale)"
    return text


def format_pull_hint(serial: Optional[str]) -> str:
    if not serial:
        return "requires device"
    status = device_service.fetch_inventory_metadata(serial)
    if not status or status.last_run_ts is None:
        return "needs inventory sync"
    count = status.package_count
    prefix = "inventory stale" if status.is_stale else "inventory ready"
    if isinstance(count, int):
        return f"{prefix} ({count} packages)"
    return prefix

