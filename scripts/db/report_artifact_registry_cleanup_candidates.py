#!/usr/bin/env python3
"""Read-only ``artifact_registry`` cleanup candidate report (no DML/DDL/deletes).

Classifies ``v_artifact_registry_integrity`` rows into policy buckets from
``docs/maintenance/artifact_registry_cleanup_track.md`` for operator triage.

Use this to decide **what** is safe to drop from the derived ledger; **actual** age-gated
``artifact_registry`` deletes are done by ``scripts/db/prune_artifact_registry_dangling.py``
(receipt + ``--apply``), not by this script.

Run from repo root::

  PYTHONPATH=. python scripts/db/report_artifact_registry_cleanup_candidates.py
  PYTHONPATH=. python scripts/db/report_artifact_registry_cleanup_candidates.py --json
  PYTHONPATH=. python scripts/db/report_artifact_registry_cleanup_candidates.py --run-type static --path-sample 40

Exit codes: 0 success, 1 import/arg error, 2 DB unavailable/query failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON (read-only).",
    )
    p.add_argument(
        "--run-type",
        choices=("static", "dynamic"),
        default=None,
        help="Restrict rows to one run_type before classification.",
    )
    p.add_argument(
        "--recent-days",
        type=int,
        default=7,
        metavar="N",
        help="Recent window for dangling_recent_keep (default: 7).",
    )
    p.add_argument(
        "--old-days",
        type=int,
        default=90,
        metavar="N",
        help="Age threshold for old vs mid static SAR-gap splits (default: 90).",
    )
    p.add_argument(
        "--path-sample",
        type=int,
        default=0,
        metavar="N",
        help="Probe up to N host_path rows (file-backed categories only; default 0).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.artifact_registry_cleanup_report import (
            collect_cleanup_candidate_report,
            format_text_report,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    try:
        data = collect_cleanup_candidate_report(
            core_q.run_sql,
            recent_days=int(args.recent_days),
            old_days=int(args.old_days),
            run_type_filter=args.run_type,
            path_sample_limit=int(args.path_sample),
            repo_root=_REPO_ROOT,
        )
    except Exception as exc:
        sys.stderr.write(f"Report failed: {exc}\n")
        return 2

    if args.json:
        sys.stdout.write(json.dumps(data, indent=2, default=str) + "\n")
    else:
        sys.stdout.write(format_text_report(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
