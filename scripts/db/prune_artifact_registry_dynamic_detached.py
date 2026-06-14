#!/usr/bin/env python3
"""Receipt-first prune for detached dynamic ``artifact_registry`` rows only.

This script targets only rows already classified by the dynamic dangling audit
as ``truly_detached``. It never deletes files and never touches any table other
than ``artifact_registry``.

Examples:

  PYTHONPATH=. python scripts/db/prune_artifact_registry_dynamic_detached.py \
    --receipt-dir data/state/artifact_registry_dynamic_prune

  PYTHONPATH=. python scripts/db/prune_artifact_registry_dynamic_detached.py \
    --receipt-dir data/state/artifact_registry_dynamic_prune --apply
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--receipt-dir",
        type=Path,
        default=_REPO_ROOT / "data" / "state" / "artifact_registry_dynamic_prune",
        help="Write timestamped JSON/CSV/SQL/run_id receipt bundle here.",
    )
    p.add_argument(
        "--expected-count",
        type=int,
        default=750,
        help="Refuse prune unless the detached dynamic candidate count matches exactly (default: 750).",
    )
    p.add_argument(
        "--expected-run-count",
        type=int,
        default=30,
        help="Refuse prune unless the detached dynamic run-id count matches exactly (default: 30).",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help="Delete the verified target rows after writing the receipt bundle.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Print the proposal/apply summary JSON to stdout.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_core.session import database_session
        from scytaledroid.Database.db_utils.artifact_registry_dynamic_prune import (
            apply_dynamic_prune,
            build_dynamic_prune_proposal,
            validate_dynamic_prune_proposal,
            write_dynamic_prune_receipts,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"artifact_registry_dynamic_prune_{stamp}"

    try:
        proposal = build_dynamic_prune_proposal(
            core_q.run_sql,
            repo_root=_REPO_ROOT,
            expected_count=int(args.expected_count),
            expected_run_count=int(args.expected_run_count),
        )
        receipt_paths = write_dynamic_prune_receipts(
            args.receipt_dir,
            stem=stem,
            proposal=proposal,
            apply_requested=bool(args.apply),
            apply_result=None,
        )

        summary = {
            "mode": "apply" if args.apply else "dry_run",
            "receipt_paths": receipt_paths,
            "targeted_row_count": proposal.targeted_row_count,
            "targeted_distinct_dynamic_run_ids": proposal.targeted_distinct_dynamic_run_ids,
            "reason_counts": proposal.reason_counts,
            "total_artifact_registry_rows_before": proposal.total_rows_before,
            "dynamic_dangling_rows_before": proposal.dynamic_dangling_before,
            "static_dangling_rows_before": proposal.static_dangling_before,
            "all_truly_detached": proposal.all_truly_detached,
            "all_dynamic_run_id_populated": proposal.all_dynamic_run_id_populated,
            "all_missing_dynamic_sessions": proposal.all_missing_dynamic_sessions,
            "all_missing_dynamic_db_refs": proposal.all_missing_dynamic_db_refs,
            "all_target_files_missing": proposal.all_target_files_missing,
            "malformed_dynamic_run_id_count": proposal.malformed_dynamic_run_id_count,
            "unknown_needs_review_count": proposal.unknown_needs_review_count,
        }

        validate_dynamic_prune_proposal(
            proposal,
            expected_count=int(args.expected_count),
            expected_run_count=int(args.expected_run_count),
        )

        if args.apply:
            with database_session() as db:
                with db.transaction():
                    proposal_txn = build_dynamic_prune_proposal(
                        core_q.run_sql,
                        repo_root=_REPO_ROOT,
                        expected_count=int(args.expected_count),
                        expected_run_count=int(args.expected_run_count),
                    )
                    validate_dynamic_prune_proposal(
                        proposal_txn,
                        expected_count=int(args.expected_count),
                        expected_run_count=int(args.expected_run_count),
                    )
                    apply_result = apply_dynamic_prune(
                        core_q.run_sql,
                        core_q.run_sql_rowcount,
                        proposal=proposal_txn,
                    )
                summary.update(
                    {
                        "deleted_count": apply_result.deleted_count,
                        "total_artifact_registry_rows_after": apply_result.total_rows_after,
                        "dynamic_dangling_rows_after": apply_result.dynamic_dangling_after,
                        "static_dangling_rows_after": apply_result.static_dangling_after,
                        "parity_after": apply_result.parity_after,
                    }
                )
            write_dynamic_prune_receipts(
                args.receipt_dir,
                stem=stem,
                proposal=proposal,
                apply_requested=True,
                apply_result=apply_result,
            )

        if args.json:
            sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
            return 0

        print("# artifact_registry dynamic prune")
        print(f"mode: {summary['mode']}")
        print(f"targeted_row_count: {summary['targeted_row_count']}")
        print(f"targeted_distinct_dynamic_run_ids: {summary['targeted_distinct_dynamic_run_ids']}")
        print(f"reason_counts: {json.dumps(summary['reason_counts'], sort_keys=True)}")
        print(f"total_artifact_registry_rows_before: {summary['total_artifact_registry_rows_before']}")
        print(f"dynamic_dangling_rows_before: {summary['dynamic_dangling_rows_before']}")
        if args.apply:
            print(f"deleted_count: {summary['deleted_count']}")
            print(f"total_artifact_registry_rows_after: {summary['total_artifact_registry_rows_after']}")
            print(f"dynamic_dangling_rows_after: {summary['dynamic_dangling_rows_after']}")
        print("receipt files:")
        for key, value in sorted(receipt_paths.items()):
            print(f"  {key}: {value}")
        if not args.apply:
            print("dry-run only")
        return 0
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"dynamic prune failed: {type(exc).__name__}: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
