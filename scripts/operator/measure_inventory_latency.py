#!/usr/bin/env python3
"""Headless inventory sync timing (no TUI menus)."""

from __future__ import annotations

import os
import sys
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def main() -> int:
    from scytaledroid.DeviceAnalysis import device_manager
    from scytaledroid.DeviceAnalysis.inventory.cli_labels import SECTION_HEADLINE
    from scytaledroid.DeviceAnalysis.services import inventory_service
    from scytaledroid.Utils.LoggingUtils import logging_utils as log

    parser = ArgumentParser(
        description=f"{SECTION_HEADLINE} — measure end-to-end duration without menus.",
        formatter_class=RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s
  %(prog)s --serial ZY22JK89DR
  %(prog)s   # respects SCYTALEDROID_INVENTORY_MODE and active device state

Writes detailed phase timings to logs (device_analysis / inventory categories).
progress_sink=None suppresses banners and interactive progress.""",
    )
    parser.add_argument("--serial", help="Device serial (default: active device).")
    args = parser.parse_args()

    serial = args.serial or device_manager.get_active_serial()
    if not serial:
        print("No device serial. Use --serial or select an active device in the Devices hub.")
        return 1

    mode = os.getenv("SCYTALEDROID_INVENTORY_MODE", "baseline")
    print(f"{SECTION_HEADLINE} (benchmark) · serial={serial} · mode={mode}")
    print("Progress UI off; check logs for collect / persist / timing breakdown.")

    try:
        inventory_service.run_full_sync(serial=serial, ui_prefs=None, progress_sink=None)
    except Exception as exc:  # pragma: no cover - CLI convenience
        log.error(f"Inventory sync failed: {exc}", category="inventory")
        print(f"Failed: {exc}")
        return 1

    print("Completed. See logging output for timings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
