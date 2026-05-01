"""
Quick scope diagnostics for the latest inventory snapshot.

Run this to see how many packages exist per scope (Social/Messaging/etc),
how many survive default harvest policies (Play installer or /data path),
and which packages are filtered out (with sample names).

Usage:
    python scripts/operator/diagnose_scope.py [serial]

If no serial is provided, the active device (if any) is used.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from scytaledroid.DeviceAnalysis.harvest.scope import InventoryRow
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

def _imports():  # noqa: ANN202 - small script helper
    # Local import so this script can be run both as `python ...` and with repo-root sys.path tweak.
    from scytaledroid.DeviceAnalysis import device_manager
    from scytaledroid.DeviceAnalysis.harvest import rules
    from scytaledroid.DeviceAnalysis.harvest.scope import InventoryRow
    from scytaledroid.DeviceAnalysis.harvest.scope_context import (
        apply_default_scope,
        build_inventory_rows,
        build_scope_context,
        collect_exclusion_samples,
    )
    from scytaledroid.DeviceAnalysis.inventory import snapshot_io

    return (
        device_manager,
        rules,
        InventoryRow,
        apply_default_scope,
        build_inventory_rows,
        build_scope_context,
        collect_exclusion_samples,
        snapshot_io,
    )


def _load_serial(arg_serial: str | None) -> str | None:
    device_manager, *_ = _imports()
    if arg_serial:
        return arg_serial
    active = device_manager.get_active_device()
    if active:
        return active.get("serial")
    return None


def _fetch_rows(serial: str):  # noqa: ANN201 - script utility
    (
        _device_manager,
        _rules,
        InventoryRow,
        _apply_default_scope,
        build_inventory_rows,
        _build_scope_context,
        _collect_exclusion_samples,
        snapshot_io,
    ) = _imports()
    snapshot = snapshot_io.load_latest_inventory(serial)
    if not snapshot:
        print(f"[WARN] No inventory snapshot found for {serial}.")
        return []
    packages = snapshot.get("packages") or []
    if not isinstance(packages, list):
        print(f"[WARN] Snapshot for {serial} contains no package list.")
        return []
    return build_inventory_rows(packages)


def _describe_exclusions(excluded: dict[str, int]) -> str:
    from scytaledroid.DeviceAnalysis.harvest.summary import _EXCLUSION_LABELS  # type: ignore

    parts = []
    for reason, count in sorted(excluded.items(), key=lambda x: x[0]):
        label = _EXCLUSION_LABELS.get(reason, reason)
        parts.append(f"{label}={count}")
    return "; ".join(parts) if parts else "none"


def _print_scope(label: str, rows: Sequence[InventoryRow], allow: set[str]) -> None:
    (
        _device_manager,
        _rules,
        _InventoryRow,
        apply_default_scope,
        _build_inventory_rows,
        _build_scope_context,
        collect_exclusion_samples,
        _snapshot_io,
    ) = _imports()
    filtered, excluded_counts = apply_default_scope(rows, allow)
    candidates = len(rows)
    kept = len(filtered)
    excluded_samples = collect_exclusion_samples(rows, filtered, allow)
    filtered_total = max(candidates - kept, 0)
    print(f"\n{label}")
    print("-" * len(label))
    print(f"candidates: {candidates} • kept: {kept} • filtered: {filtered_total}")
    print(f"filtered breakdown: {_describe_exclusions(excluded_counts)}")
    if excluded_samples:
        print("sample filtered packages:")
        for reason, names in excluded_samples.items():
            if not names:
                continue
            print(f"  {reason}: {', '.join(names)}")


def _category_group(rows: Sequence[InventoryRow]) -> dict[str, list[InventoryRow]]:
    (
        _device_manager,
        rules,
        _InventoryRow,
        _apply_default_scope,
        _build_inventory_rows,
        build_scope_context,
        _collect_exclusion_samples,
        _snapshot_io,
    ) = _imports()
    context = build_scope_context(rows, set(rules.GOOGLE_ALLOWLIST))
    return context.get("category_groups", {}) or {}


def main(serial: str | None) -> int:
    serial = _load_serial(serial)
    if not serial:
        print("[ERROR] No device serial provided and no active device found.")
        return 1

    rows = _fetch_rows(serial)
    if not rows:
        return 1

    (
        _device_manager,
        rules,
        _InventoryRow,
        _apply_default_scope,
        _build_inventory_rows,
        _build_scope_context,
        _collect_exclusion_samples,
        _snapshot_io,
    ) = _imports()
    allow = set(rules.GOOGLE_ALLOWLIST)

    print(f"[INFO] Scope diagnostics for {serial}")
    print(f"[INFO] Total inventory packages: {len(rows)}")

    # Default scope
    _print_scope("Default scope (Play + /data user apps)", rows, allow)

    # Social/Messaging category groups
    groups = _category_group(rows)
    social = groups.get("Social", [])
    messaging = groups.get("Messaging", [])
    combined = social + messaging
    if social:
        _print_scope("Social category", social, allow)
    if messaging:
        _print_scope("Messaging category", messaging, allow)
    if combined:
        _print_scope("Social + Messaging combined", combined, allow)
    else:
        print("[INFO] No Social or Messaging packages detected in inventory categories.")

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Diagnose harvest scope counts from the latest inventory snapshot.")
    parser.add_argument("serial", nargs="?", help="Device serial. Defaults to active device.")
    args = parser.parse_args()
    raise SystemExit(main(args.serial))
