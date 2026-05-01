#!/usr/bin/env python3
"""
Headless inventory benchmark script.

Runs an inventory sync via the service façade (no UI), prints timing
information (collect/snapshot/db/overall/per-pkg, mode) so you can compare
before/after performance changes without going through the menu.
"""

from __future__ import annotations

import os
import sys
from argparse import ArgumentParser
from pathlib import Path

# Ensure project root is on sys.path when run from scripts/.
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def main() -> int:
    from scytaledroid.DeviceAnalysis import device_manager
    from scytaledroid.DeviceAnalysis.services import inventory_service
    from scytaledroid.Utils.LoggingUtils import logging_utils as log

    parser = ArgumentParser(description="Measure inventory sync timing headlessly.")
    parser.add_argument(
        "--serial",
        help="Device serial to target. Defaults to active device.",
    )
    args = parser.parse_args()

    serial = args.serial or device_manager.get_active_serial()
    if not serial:
        print("No active device. Specify --serial or set an active device first.")
        return 1

    mode = os.getenv("SCYTALEDROID_INVENTORY_MODE", "baseline")
    print(f"[INFO] Running inventory sync for {serial} (mode={mode})...")

    try:
        # progress_sink=None to suppress UI; service will still log timing.
        inventory_service.run_full_sync(serial=serial, ui_prefs=None, progress_sink=None)
    except Exception as exc:  # pragma: no cover - CLI convenience
        log.error(f"Inventory sync failed: {exc}", category="inventory")
        print(f"[ERROR] Inventory sync failed: {exc}")
        return 1

    print(f"[INFO] Inventory sync completed (mode={mode}). Check logs for timing breakdown.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
