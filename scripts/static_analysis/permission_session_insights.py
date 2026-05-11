#!/usr/bin/env python3
"""Print permission-focused session metrics (core DB + persistence audit JSON rollup).

Example::

  PYTHONPATH=. python scripts/static_analysis/permission_session_insights.py 20260509-all-full
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session_stamp", help="session_stamp (e.g. 20260509-all-full)")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Override OUTPUT_DIR when resolving audit/persistence JSON (default: app config).",
    )
    args = parser.parse_args()

    from scytaledroid.StaticAnalysis.cli.audit.permission_session_insights import (
        render_permission_session_insights,
    )

    render_permission_session_insights(args.session_stamp.strip(), output_dir=args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
