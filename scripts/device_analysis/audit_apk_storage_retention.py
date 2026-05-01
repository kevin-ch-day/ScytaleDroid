#!/usr/bin/env python3
"""Generate a dry-run APK retention audit for the current storage tree."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.DeviceAnalysis.services import storage_retention


def _humanize_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    current = float(value)
    for unit in units:
        if current < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(current)} {unit}"
            return f"{current:.2f} {unit}"
        current /= 1024.0
    return f"{int(value)} B"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dry-run audit for APK retention candidates.")
    parser.add_argument(
        "--root",
        type=Path,
        default=storage_retention.default_storage_root(),
        help="Storage root to scan (default: data/ for canonical store + receipts).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=storage_retention.default_audit_root(),
        help="Directory for JSON/CSV audit outputs (default: output/audit/storage).",
    )
    parser.add_argument(
        "--survivor-policy",
        choices=("oldest", "newest"),
        default="oldest",
        help="Which physical copy to retain for duplicate payload groups.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full JSON audit to stdout after writing files.",
    )
    args = parser.parse_args(argv)

    audit, json_path, csv_path = storage_retention.generate_retention_audit(
        root=args.root,
        out_dir=args.out_dir,
        survivor_policy=args.survivor_policy,
    )

    summary = audit.get("summary", {})
    print("APK retention audit")
    print(f"  Root               : {args.root}")
    print(f"  Survivor policy    : {args.survivor_policy}")
    print(f"  Records scanned    : {summary.get('records_scanned', 0)}")
    print(f"  Unique identities  : {summary.get('unique_retention_keys', 0)}")
    print(f"  Duplicate groups   : {summary.get('duplicate_groups', 0)}")
    print(f"  Duplicate payloads : {summary.get('duplicate_payloads', 0)}")
    print(f"  Reclaimable bytes  : {_humanize_bytes(int(summary.get('reclaimable_bytes', 0) or 0))}")
    print(f"  JSON audit         : {json_path}")
    print(f"  CSV candidates     : {csv_path}")

    if args.json:
        print()
        print(json.dumps(audit, indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
