#!/usr/bin/env python3
"""Print post-run summary for a static session (persistence audit JSON + DB checks).

Example::

  PYTHONPATH=. python scripts/static_analysis/post_run_session_summary.py 20260509-all-full
  PYTHONPATH=. python scripts/static_analysis/post_run_session_summary.py 20260509-all-full --skip-db
"""

from __future__ import annotations

import argparse


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session_stamp", help="session_stamp (e.g. 20260509-all-full)")
    parser.add_argument(
        "--skip-db",
        action="store_true",
        help="Only read output/audit/persistence JSON (no MariaDB queries).",
    )
    parser.add_argument(
        "--skip-permission-insights",
        action="store_true",
        help="Omit the permission session insights block (only applies when DB is enabled).",
    )
    args = parser.parse_args()

    from scytaledroid.StaticAnalysis.cli.audit.post_run_session_summary import (
        render_post_run_session_summary,
    )

    render_post_run_session_summary(
        args.session_stamp.strip(),
        skip_db=bool(args.skip_db),
        interactive=False,
        skip_permission_insights=bool(args.skip_permission_insights),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
