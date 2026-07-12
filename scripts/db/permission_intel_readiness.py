#!/usr/bin/env python3
"""CLI wrapper for Permission Intel readiness (ScytaleDroid env: SCYTALEDROID_PERMISSION_INTEL_DB_*).

Example::

  PYTHONPATH=. python scripts/db/permission_intel_readiness.py
  PYTHONPATH=. python scripts/db/permission_intel_readiness.py --paper-grade

Exit code: 0 OK, 1 EXPERIMENTAL/misconfiguration, 2 ERROR (paper-grade strict failure).
"""

from __future__ import annotations

import argparse


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--paper-grade",
        action="store_true",
        help="Treat as paper-grade context (ERROR if Intel/governance not satisfied).",
    )
    args = parser.parse_args()

    from scytaledroid.Database.db_utils.permission_intel_readiness import (
        render_permission_intel_readiness,
    )

    label = render_permission_intel_readiness(paper_grade_requested=bool(args.paper_grade))
    if label == "ERROR":
        return 2
    if label == "EXPERIMENTAL":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
