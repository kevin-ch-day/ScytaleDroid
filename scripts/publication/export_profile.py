#!/usr/bin/env python3
"""Dispatch publication exports by explicit profile selection.

This script exists to make the supported OSS surface unambiguous:
- Profile v2 (frozen cohort): exports under output/publication/ (legacy-compatible surface).
- Profile v3 (structural): exports under output/publication/profile_v3/.

No "auto" mode: callers must choose a profile explicitly.
"""

from __future__ import annotations

import argparse
import runpy
import sys
import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _run(script: Path) -> None:
    if not script.exists():
        raise SystemExit(f"Missing script: {script}")
    runpy.run_path(str(script), run_name="__main__")


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
        _run(REPO_ROOT / "scripts" / "publication" / "publication_exports.py")
        if args.v2_include_results_numbers:
            _run(REPO_ROOT / "scripts" / "publication" / "publication_results_numbers.py")
        return 0

    if args.profile == "v3":
        script = REPO_ROOT / "scripts" / "publication" / "profile_v3_exports.py"
        if args.strict:
            # Pass-through strict flag by setting argv for the script's argparse.
            os.environ["SCYTALEDROID_PAPER_STRICT"] = "1"
            sys.argv = [str(script), "--strict"]
        _run(script)
        return 0

    raise SystemExit(f"Unsupported profile: {args.profile}")


if __name__ == "__main__":
    raise SystemExit(main())
