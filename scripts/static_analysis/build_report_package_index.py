#!/usr/bin/env python3
"""Build or refresh the persistent static-report package index.

Examples:

  PYTHONPATH=. python scripts/static_analysis/build_report_package_index.py
  PYTHONPATH=. python scripts/static_analysis/build_report_package_index.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--clear-warm-cache",
        action="store_true",
        help="Clear the in-process warm report cache before rebuilding.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human-readable text.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[2]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from scytaledroid.StaticAnalysis.persistence.reports import rebuild_report_package_index

    stats = rebuild_report_package_index(clear_warm_cache=bool(args.clear_warm_cache))
    payload = {
        "index_path": str(stats["index_path"]),
        "row_count": int(stats["row_count"]),
        "package_count": int(stats["package_count"]),
        "elapsed_seconds": round(float(stats["elapsed_seconds"]), 4),
        "bytes": int(stats["bytes"]),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("Static report package index")
        print("---------------------------")
        print(f"Index path     : {payload['index_path']}")
        print(f"Rows           : {payload['row_count']}")
        print(f"Packages       : {payload['package_count']}")
        print(f"Size           : {payload['bytes']} bytes")
        print(f"Elapsed        : {payload['elapsed_seconds']} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
