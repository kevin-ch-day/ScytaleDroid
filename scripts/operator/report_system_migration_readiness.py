#!/usr/bin/env python3
"""Report read-only ScytaleDroid system-migration readiness.

This preflight inventories the transfer surfaces required for a reproducible
move. It does not copy files, export a database, reveal configuration values,
or mutate local evidence.

Examples:
  PYTHONPATH=. python scripts/operator/report_system_migration_readiness.py
  PYTHONPATH=. python scripts/operator/report_system_migration_readiness.py --json
  PYTHONPATH=. python scripts/operator/report_system_migration_readiness.py --destination-root /mnt/NEW_SYSTEM
  PYTHONPATH=. python scripts/operator/report_system_migration_readiness.py --output output/audit/migration/readiness.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=_REPO_ROOT, help="Repository root to inspect.")
    parser.add_argument("--json", action="store_true", help="Print the report as JSON.")
    parser.add_argument(
        "--destination-root",
        type=Path,
        help="Optional mounted destination root for read-only capacity validation and rsync command templates.",
    )
    parser.add_argument("--output", type=Path, help="Optional explicit JSON output path; no file is written by default.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    from scytaledroid.Workspace.migration_readiness import (
        build_migration_readiness_report,
        render_migration_readiness_report,
    )

    report = build_migration_readiness_report(args.repo_root, destination_root=args.destination_root)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_migration_readiness_report(report), end="")
        if args.output:
            print(f"JSON report: {args.output}")
    return 1 if report.get("overall_status") == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
