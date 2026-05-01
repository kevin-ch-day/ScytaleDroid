"""Env-backed defaults shared across DeviceAnalysis (inventory, guard, CLI, services).

One place for these knobs so ``services`` and ``inventory.progress`` do not depend on
``device_menu`` just to read thresholds that also affect headless workflows.
"""

from __future__ import annotations

import os

INVENTORY_STALE_SECONDS = int(os.getenv("SCYTALEDROID_INVENTORY_STALE_SECONDS", 24 * 60 * 60))
INVENTORY_DELTA_SUPPRESS_SECONDS = int(
    os.getenv("SCYTALEDROID_INVENTORY_DELTA_SUPPRESS_SECONDS", 2 * 60 * 60)
)

LONG_RUNNING_SYNC_THRESHOLD = 120
LOW_BATTERY_THRESHOLD = 20

__all__ = [
    "INVENTORY_DELTA_SUPPRESS_SECONDS",
    "INVENTORY_STALE_SECONDS",
    "LONG_RUNNING_SYNC_THRESHOLD",
    "LOW_BATTERY_THRESHOLD",
]
