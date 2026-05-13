#!/usr/bin/env python3
"""Prune **old dangling** ``artifact_registry`` rows (DB only; no filesystem deletes).

Selection:

* ``v_artifact_registry_integrity.link_state <> 'linked'`` — never touches rows tied to a
  current ``static_analysis_runs`` or ``dynamic_sessions`` row.
* ``created_at_utc`` older than ``max(--min-age-days, --cooling-off-days)`` (UTC), or
  ``--include-null-created-at`` for legacy NULL timestamps (aggressive).

**Default is dry-run** (counts + optional receipt). **Deletes require** ``--apply`` **and**
``--receipt-dir`` (writes JSON/CSV/SQL receipt **before** ``DELETE``). JSON receipts use
envelope ``scytaledroid.artifact_registry_prune_receipt.v1`` (``meta`` + ``artifact_rows``).

This is a research/test ledger cleanup: harvested APKs, inventory, and Permission Intel are
out of scope — only derived registry rows.

Examples::

  PYTHONPATH=. python scripts/db/prune_artifact_registry_dangling.py --min-age-days 90
  PYTHONPATH=. python scripts/db/prune_artifact_registry_dangling.py --min-age-days 90 --sample-ids 20
  PYTHONPATH=. python scripts/db/prune_artifact_registry_dangling.py \\
    --min-age-days 120 --receipt-dir data/state/artifact_registry_prune
  PYTHONPATH=. python scripts/db/prune_artifact_registry_dangling.py \\
    --min-age-days 90 --receipt-dir data/state/artifact_registry_prune --apply

Exit codes: 0 success, 1 usage/config, 2 DB failure.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--min-age-days",
        type=int,
        default=90,
        metavar="N",
        help="Only rows with created_at_utc older than N days (UTC); combined with cooling-off as max(N, cooling) (default: 90).",
    )
    p.add_argument(
        "--cooling-off-days",
        type=int,
        default=7,
        metavar="N",
        help="Minimum age floor in days (default: 7); effective cutoff is max(--min-age-days, this).",
    )
    p.add_argument(
        "--run-type",
        choices=("static", "dynamic", "all"),
        default="all",
        help="Restrict candidates to one run_type (default: all).",
    )
    p.add_argument(
        "--include-null-created-at",
        action="store_true",
        help="Also select dangling rows with NULL created_at_utc (alpha-era; use sparingly).",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Cap candidates (debug/safety); 0 = no cap (default: 0).",
    )
    p.add_argument(
        "--receipt-dir",
        type=Path,
        default=None,
        help="Write timestamped JSON/CSV/SQL receipt bundle under this directory.",
    )
    p.add_argument(
        "--receipt-formats",
        type=str,
        default="json,csv,sql",
        help="Comma-separated subset of json,csv,sql (default: json,csv,sql).",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help="Perform DELETE after writing receipt (requires --receipt-dir when candidates exist).",
    )
    p.add_argument(
        "--sample-ids",
        type=int,
        default=0,
        metavar="N",
        help="After counts, print the first N candidate artifact_id values (default: 0).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.artifact_registry_prune import (
            run_prune_dangling_artifact_registry,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    rt = str(args.run_type or "all").strip().lower()
    run_type_filter = None if rt == "all" else rt

    fmts_raw = str(args.receipt_formats or "").lower().split(",")
    receipt_formats = {x.strip() for x in fmts_raw if x.strip() in {"json", "csv", "sql"}}
    if not receipt_formats:
        sys.stderr.write("No valid --receipt-formats (use json, csv, sql).\n")
        return 1

    receipt_dir = args.receipt_dir
    apply = bool(args.apply)

    try:
        result = run_prune_dangling_artifact_registry(
            core_q.run_sql,
            core_q.run_sql_rowcount,
            min_age_days=int(args.min_age_days),
            cooling_off_days=int(args.cooling_off_days),
            run_type_filter=run_type_filter,
            include_null_created_at=bool(args.include_null_created_at),
            limit=int(args.limit),
            receipt_dir=receipt_dir,
            receipt_formats=receipt_formats,
            apply=apply,
            sample_id_limit=int(args.sample_ids),
        )
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"Prune operation failed: {exc}\n")
        return 2

    print(f"artifact_registry total rows (before): {result.total_rows_before}")
    print(f"effective cutoff age (days, UTC): {result.cutoff_days}")
    print(f"candidate dangling rows: {result.candidate_count}")
    if result.sample_artifact_ids:
        joined = ", ".join(str(x) for x in result.sample_artifact_ids)
        print(f"sample artifact_id values (first {len(result.sample_artifact_ids)}): {joined}")
    if result.receipt_paths:
        print("receipt files:")
        for k, v in sorted(result.receipt_paths.items()):
            print(f"  {k}: {v}")
    if apply:
        print(f"deleted artifact_registry rows: {result.deleted_count}")
        if result.total_rows_after is not None:
            print(f"artifact_registry total rows (after): {result.total_rows_after}")
        elif result.candidate_count == 0:
            print("no candidates to delete (artifact_registry unchanged).")
    else:
        print("dry-run only (no DELETE). Pass --apply with --receipt-dir to delete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
