#!/usr/bin/env python3
"""Migrate legacy harvest package trees into canonical store/receipts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.DeviceAnalysis.services.legacy_harvest_migration import (
    migrate_legacy_harvest_tree,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migrate legacy harvest data into canonical store/receipts")
    parser.add_argument(
        "--source-root",
        help="Legacy harvest root (default: data/device_apks)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit summary as JSON",
    )
    args = parser.parse_args(argv)

    source_root = Path(args.source_root).expanduser().resolve() if args.source_root else None
    summary = migrate_legacy_harvest_tree(source_root)

    if args.json:
        print(json.dumps(summary.__dict__, indent=2, sort_keys=True))
    else:
        print("Legacy harvest migration")
        print("------------------------")
        print(f"Manifests scanned   : {summary.manifests_scanned}")
        print(f"Artifacts scanned   : {summary.artifacts_scanned}")
        print(f"Artifacts stored    : {summary.artifacts_materialized}")
        print(f"Sidecars written    : {summary.sidecars_written}")
        print(f"Receipts written    : {summary.receipts_written}")
        print(f"Errors              : {len(summary.errors)}")
        for item in summary.errors[:20]:
            print(f"- {item}")
    return 0 if not summary.errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
