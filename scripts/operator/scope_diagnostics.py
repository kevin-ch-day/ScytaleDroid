"""
Quick scope diagnostics for the latest inventory snapshot.

Run this to see how many packages exist per scope (Social/Messaging/etc),
how many survive default harvest policies (Play installer or /data path),
and which packages are filtered out (with sample names).

Usage:
    python scripts/scope_diagnostics.py [serial]

If no serial is provided, the active device (if any) is used.
"""

from __future__ import annotations

import sys
from typing import Dict, Iterable, List, Sequence, Set, Tuple

from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DeviceAnalysis.inventory import snapshot_io
from scytaledroid.DeviceAnalysis.harvest import scope as scope_mod
from scytaledroid.DeviceAnalysis.harvest.scope import InventoryRow
from scytaledroid.DeviceAnalysis.harvest import rules


def _load_serial(arg_serial: str | None) -> str | None:
    if arg_serial:
        return arg_serial
    active = device_manager.get_active_device()
    if active:
        return active.get("serial")
    return None


def _fetch_rows(serial: str) -> List[InventoryRow]:
    snapshot = snapshot_io.load_latest_inventory(serial)
    if not snapshot:
        print(f"[WARN] No inventory snapshot found for {serial}.")
        return []
    packages = snapshot.get("packages") or []
    if not isinstance(packages, list):
        print(f"[WARN] Snapshot for {serial} contains no package list.")
        return []
    return scope_mod.build_inventory_rows(packages)


def _counts_by_reason(
    rows: Sequence[InventoryRow],
    kept: Sequence[InventoryRow],
    allow: Set[str],
) -> Tuple[int, int, Dict[str, int], Dict[str, List[str]]]:
    excluded_counts: Dict[str, int] = {}
    kept_names = {row.package_name for row in kept}
    excluded_samples = scope_mod._collect_exclusion_samples(rows, kept, allow)  # type: ignore[attr-defined]
    for row in rows:
        if row.package_name in kept_names:
            continue
        include, reason = scope_mod._default_scope_decision(row, allow)  # type: ignore[attr-defined]
        if include or not reason:
            continue
        excluded_counts[reason] = excluded_counts.get(reason, 0) + 1
    return len(rows), len(kept), excluded_counts, excluded_samples


def _describe_exclusions(excluded: Dict[str, int]) -> str:
    from scytaledroid.DeviceAnalysis.harvest.summary import _EXCLUSION_LABELS  # type: ignore

    parts = []
    for reason, count in sorted(excluded.items(), key=lambda x: x[0]):
        label = _EXCLUSION_LABELS.get(reason, reason)
        parts.append(f"{label}={count}")
    return "; ".join(parts) if parts else "none"


def _print_scope(label: str, rows: Sequence[InventoryRow], allow: Set[str]) -> None:
    filtered, excluded = scope_mod._apply_default_scope(rows, allow)  # type: ignore[attr-defined]
    candidates, kept, excluded_counts, excluded_samples = _counts_by_reason(rows, filtered, allow)
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


def _category_group(rows: Sequence[InventoryRow]) -> Dict[str, List[InventoryRow]]:
    category_map = scope_mod._fetch_category_map([row.package_name for row in rows])  # type: ignore[attr-defined]
    groups: Dict[str, List[InventoryRow]] = {}
    for row in rows:
        category_name = category_map.get(row.package_name) or row.profile
        if category_name:
            groups.setdefault(category_name, []).append(row)
    return groups


def main(serial: str | None) -> int:
    serial = _load_serial(serial)
    if not serial:
        print("[ERROR] No device serial provided and no active device found.")
        return 1

    rows = _fetch_rows(serial)
    if not rows:
        return 1

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
    serial_arg = sys.argv[1] if len(sys.argv) > 1 else None
    raise SystemExit(main(serial_arg))
