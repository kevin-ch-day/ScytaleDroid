#!/usr/bin/env python3
"""Per-app permission drilldown (core DB + optional report JSON for raw declarations).

Provide ``--session-stamp`` and ``--package``, or ``--static-run-id`` alone.

Example::

  PYTHONPATH=. python scripts/static_analysis/permission_app_drilldown.py \\
    --session-stamp 20260509-all-full --package com.example.app

  PYTHONPATH=. python scripts/static_analysis/permission_app_drilldown.py \\
    --static-run-id 12345 --report data/static_analysis/reports/latest/<sha>.json
"""

from __future__ import annotations

import argparse


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-stamp", default=None, help="Session stamp (with --package).")
    parser.add_argument("--package", default=None, help="Application package name.")
    parser.add_argument("--static-run-id", type=int, default=None, help="static_analysis_runs.id")
    parser.add_argument(
        "--report",
        default=None,
        help="Optional report JSON path (declared permissions from manifest snapshot).",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Override OUTPUT_DIR when resolving persistence audit JSON.",
    )
    args = parser.parse_args()
    sid = args.static_run_id
    stamp = (args.session_stamp or "").strip() or None
    pkg = (args.package or "").strip() or None
    if sid is None and (not stamp or not pkg):
        parser.error("Provide --static-run-id, or both --session-stamp and --package.")

    from scytaledroid.StaticAnalysis.cli.audit.permission_app_drilldown import (
        render_permission_app_drilldown,
    )

    render_permission_app_drilldown(
        session_stamp=stamp,
        package_name=pkg,
        static_run_id=sid,
        report_path=args.report,
        output_dir=args.output_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
