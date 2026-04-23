#!/usr/bin/env python3
"""Backfill dynamic_network_features from local dynamic evidence packs."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.storage.feature_backfill import (  # noqa: E402
    backfill_missing_dynamic_network_features,
    list_missing_feature_candidates,
)

ENV_FILE = Path(os.environ.get("SCYTALEDROID_ENV_FILE", REPO_ROOT / ".env"))


def _load_env() -> None:
    if not ENV_FILE.exists():
        return
    for raw in ENV_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Backfill missing dynamic_network_features rows from local evidence packs."
    )
    parser.add_argument("--limit", type=int, default=None, help="Maximum missing rows to inspect.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply upserts. Default is dry-run only.",
    )
    parser.add_argument(
        "--show-missing",
        type=int,
        default=10,
        help="Print up to N missing-evidence examples in dry-run output.",
    )
    args = parser.parse_args()

    _load_env()
    dry_run = not args.apply
    result = backfill_missing_dynamic_network_features(limit=args.limit, dry_run=dry_run)

    mode = "DRY RUN" if dry_run else "APPLY"
    print(f"Dynamic network feature backfill ({mode})")
    print("--------------------------------------")
    print(f"scanned          : {result.scanned}")
    print(f"buildable        : {result.buildable}")
    print(f"missing_evidence : {result.missing_evidence}")
    print(f"upserted         : {result.upserted}")
    print(f"low_signal_rows  : {result.low_signal_upserted}")
    if result.errors:
        print("errors           :")
        for error in result.errors:
            print(f"  - {error}")

    if dry_run and args.show_missing > 0:
        missing = [
            candidate
            for candidate in list_missing_feature_candidates(limit=args.limit)
            if not candidate.evidence_exists
        ][: max(0, args.show_missing)]
        if missing:
            print()
            print("Missing evidence examples")
            print("-------------------------")
            for candidate in missing:
                print(f"{candidate.dynamic_run_id} | {candidate.package_name} | {candidate.evidence_path}")

    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
