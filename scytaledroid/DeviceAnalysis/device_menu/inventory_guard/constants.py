"""Constants shared across inventory guard helpers."""
import os

INVENTORY_STALE_SECONDS = int(os.getenv("SCYTALEDROID_INVENTORY_STALE_SECONDS", 24 * 60 * 60))
LONG_RUNNING_SYNC_THRESHOLD = 120
LOW_BATTERY_THRESHOLD = 20
