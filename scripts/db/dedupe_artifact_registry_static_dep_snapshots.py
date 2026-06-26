#!/usr/bin/env python3
"""Deduplicate static ``dep_snapshot`` artifact_registry rows (DB only; no file deletes).

Default mode is dry-run. When duplicate rows exist, a receipt directory is
required so candidate ids and keep/delete groups are exported before apply.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=None,
        help="Write JSON/CSV/SQL receipt files here.",
    )
    parser.add_argument("--apply", action="store_true", help="Delete duplicate rows after writing receipt files.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.artifact_registry_static_dep_snapshot_dedupe import (
            apply_static_dep_snapshot_dedupe,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    try:
        proposal, result, receipt_paths = apply_static_dep_snapshot_dedupe(
            core_q.run_sql,
            core_q.run_sql_rowcount,
            receipt_dir=args.receipt_dir,
            apply=bool(args.apply),
        )
    except Exception as exc:
        sys.stderr.write(f"static dep_snapshot dedupe failed: {exc}\n")
        return 2

    payload = {
        "apply": bool(args.apply),
        "duplicate_group_count": proposal.duplicate_group_count,
        "duplicate_row_count": proposal.duplicate_row_count,
        "affected_run_count": proposal.affected_run_count,
        "candidate_delete_count": len(proposal.candidate_delete_ids),
        "receipt_paths": receipt_paths,
        "result": {
            "deleted_count": int(result.deleted_count),
            "duplicate_group_count_after": int(result.duplicate_group_count_after),
            "duplicate_row_count_after": int(result.duplicate_row_count_after),
        }
        if result is not None
        else None,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    print("# artifact_registry static dep_snapshot dedupe")
    print(f"duplicate_group_count: {proposal.duplicate_group_count}")
    print(f"duplicate_row_count: {proposal.duplicate_row_count}")
    print(f"affected_run_count: {proposal.affected_run_count}")
    print(f"candidate_delete_count: {len(proposal.candidate_delete_ids)}")
    if receipt_paths:
        print("receipt files:")
        for key, path in sorted(receipt_paths.items()):
            print(f"  {key}: {path}")
    if result is None:
        print("dry-run only (no DELETE). Use --apply with --receipt-dir to delete duplicates.")
    else:
        print(f"deleted_count: {result.deleted_count}")
        print(f"duplicate_group_count_after: {result.duplicate_group_count_after}")
        print(f"duplicate_row_count_after: {result.duplicate_row_count_after}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
