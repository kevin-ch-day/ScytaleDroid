#!/usr/bin/env python3
"""Dispatch publication exports by explicit profile selection.

This script exists to make the supported OSS surface unambiguous:
- Profile v2 (frozen cohort): exports under output/publication/ (legacy-compatible surface).
- Profile v3 (structural): exports under output/publication/profile_v3/.

No "auto" mode: callers must choose a profile explicitly.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Reporting.services.profile_v3_exports_service import main as run_profile_v3_exports
from scytaledroid.Reporting.services.publication_exports_service import generate_publication_exports
from scytaledroid.Reporting.services.publication_results_numbers_service import generate_results_numbers


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Dispatch publication exports by profile (explicit)")
    p.add_argument("--profile", required=True, choices=["v2", "v3"], help="Export profile to run.")
    p.add_argument(
        "--v2-include-results-numbers",
        action="store_true",
        help="Also generate v2 manuscript numbers/blocks (publication_results_numbers.py).",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Enable paper/demo strict mode for the selected profile (when supported).",
    )
    args = p.parse_args(argv)

    if args.profile == "v2":
        generate_publication_exports()
        if args.v2_include_results_numbers:
            generate_results_numbers()
        return 0

    if args.profile == "v3":
        if args.strict:
            os.environ["SCYTALEDROID_PAPER_STRICT"] = "1"
        return run_profile_v3_exports(["--strict"] if args.strict else [])

    raise SystemExit(f"Unsupported profile: {args.profile}")


if __name__ == "__main__":
    raise SystemExit(main())
