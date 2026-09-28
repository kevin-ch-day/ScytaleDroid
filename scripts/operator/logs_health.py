#!/usr/bin/env python3
"""Report ScytaleDroid log storage and age signals without changing files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=None,
        help="Log root; defaults to SCYTALEDROID_LOGS_DIR or logs/.",
    )
    parser.add_argument(
        "--older-than-days", type=int, default=None, help="Flag files older than this many days."
    )
    parser.add_argument(
        "--top", type=int, default=10, help="Number of largest files to show (default: 10)."
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit the complete machine-readable report."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from scytaledroid.Utils.System.log_health import collect_log_health, render_log_health

    try:
        report = collect_log_health(
            args.log_dir,
            older_than_days=args.older_than_days,
            largest_limit=args.top,
        )
    except ValueError as exc:
        _build_parser().error(str(exc))

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_log_health(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
