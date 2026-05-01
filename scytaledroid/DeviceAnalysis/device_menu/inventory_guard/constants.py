"""Constants shared across inventory guard helpers."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.device_analysis_settings import (
    INVENTORY_DELTA_SUPPRESS_SECONDS,
    INVENTORY_STALE_SECONDS,
    LONG_RUNNING_SYNC_THRESHOLD,
    LOW_BATTERY_THRESHOLD,
)

__all__ = [
    "INVENTORY_DELTA_SUPPRESS_SECONDS",
    "INVENTORY_STALE_SECONDS",
    "LONG_RUNNING_SYNC_THRESHOLD",
    "LOW_BATTERY_THRESHOLD",
]
