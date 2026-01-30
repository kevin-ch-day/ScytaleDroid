"""
Dry-run a harvest scope and show candidates/kept/filtered breakdown without pulling APKs.

Usage:
    python scripts/dev/dump_harvest_plan.py [--serial SERIAL] [--scope default|social_messaging|google_user|everything] [--include-system]
"""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional, Sequence, Set

from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DeviceAnalysis.harvest import planner, rules, scope
from scytaledroid.DeviceAnalysis.harvest.models import InventoryRow, ScopeSelection
from scytaledroid.DeviceAnalysis.inventory import snapshot_io


def _load_serial(serial_arg: Optional[str]) -> Optional[str]:
    if serial_arg:
        return serial_arg
    active = device_manager.get_active_device()
    if active:
        return active.get("serial")
    return None


def _load_rows(serial: str) -> List[InventoryRow]:
    snapshot = snapshot_io.load_latest_inventory(serial)
    if not snapshot:
        print(f"[ERROR] No inventory snapshot found for {serial}. Run inventory sync first.")
        return []
    packages = snapshot.get("packages") or []
    if not isinstance(packages, list):
        print(f"[ERROR] Snapshot for {serial} contains no package list.")
        return []
    return scope.build_inventory_rows(packages)


def _resolve_scope(
    name: str,
    rows: Sequence[InventoryRow],
    allow: Set[str],
) -> Optional[ScopeSelection]:
    if name == "default":
        return scope._scope_default(rows, allow)  # type: ignore[attr-defined]
    if name == "social_messaging":
        context = scope._build_scope_context(rows, allow)  # type: ignore[attr-defined]
        category_groups = context.get("category_groups") or {}
        return scope._scope_category_subset(  # type: ignore[attr-defined]
            category_groups,
            allow,
            {"Social", "Messaging"},
            label="Social & Messaging",
        )
    if name == "google_user":
        return scope._scope_google_user_apps(rows, allow)  # type: ignore[attr-defined]
    if name == "everything":
        meta = {"candidate_count": len(rows), "selected_count": len(rows)}
        return ScopeSelection("Everything", list(rows), "everything", meta)
    print(f"[ERROR] Unknown scope '{name}'.")
    return None


def _print_scope(selection: ScopeSelection, plan) -> None:
    meta = selection.metadata or {}
    candidates = int(meta.get("candidate_count") or 0)
    selected = int(meta.get("selected_count") or len(selection.packages))
    excluded_counts: Dict[str, int] = meta.get("excluded_counts") or {}
    if not candidates:
        candidates = selected + sum(int(v) for v in excluded_counts.values())
    filtered = max(candidates - selected, 0)

    print(f"Scope: {selection.label}")
    print(f"Candidates : {candidates}")
    print(f"Kept       : {selected}")
    print(f"Filtered   : {filtered}")

    if excluded_counts:
        print("\nFiltered by scope policy:")
        for reason, count in sorted(excluded_counts.items(), key=lambda item: -int(item[1])):
            print(f"  - {reason}: {count}")

    if plan.policy_filtered:
        print("\nFiltered by harvest policy (non-root/system/etc.):")
        for reason, count in sorted(plan.policy_filtered.items(), key=lambda item: -int(item[1])):
            print(f"  - {reason}: {count}")

    samples = meta.get("excluded_samples") or {}
    if samples:
        print("\nExamples of filtered packages:")
        for reason, names in samples.items():
            if not names:
                continue
            preview = ", ".join(names[:5])
            more = len(names) - len(names[:5])
            suffix = f", +{more} more" if more > 0 else ""
            print(f"  - {reason}: {preview}{suffix}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Dry-run harvest planning for a scope.")
    parser.add_argument("--serial", help="Device serial (defaults to active device).")
    parser.add_argument(
        "--scope",
        choices=["default", "social_messaging", "google_user", "everything"],
        default="default",
        help="Scope to simulate.",
    )
    parser.add_argument(
        "--include-system",
        action="store_true",
        help="Include system/vendor partitions (requires root).",
    )
    args = parser.parse_args(argv)

    serial = _load_serial(args.serial)
    if not serial:
        print("[ERROR] No device serial provided and no active device found.")
        return 1

    rows = _load_rows(serial)
    if not rows:
        return 1

    allow = set(rules.GOOGLE_ALLOWLIST)
    selection = _resolve_scope(args.scope, rows, allow)
    if selection is None:
        return 1

    plan = planner.build_harvest_plan(selection.packages, include_system_partitions=args.include_system)
    _print_scope(selection, plan)
    return 0


if __name__ == "__main__":
    sys.exit(main())
