#!/usr/bin/env python3
"""Receipt-first prune for detached static ``artifact_registry`` rows only.

This script targets only rows already classified by the static dangling audit
as conservative detached buckets. It never deletes files and never touches any
table other than ``artifact_registry``.

Examples:

  PYTHONPATH=. python scripts/db/prune_artifact_registry_static_detached.py \
    --receipt-dir data/state/artifact_registry_static_prune

  PYTHONPATH=. python scripts/db/prune_artifact_registry_static_detached.py \
    --receipt-dir data/state/artifact_registry_static_prune --include-legacy-mirror-missing
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
        default=_REPO_ROOT / "data" / "state" / "artifact_registry_static_prune",
        help="Write timestamped JSON/CSV/SQL/run_id receipt bundle here.",
    )
    p.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="Optional exact target count guard; apply is refused if the proposal count differs.",
    )
    p.add_argument(
        "--include-legacy-mirror-missing",
        action="store_true",
        help="Also target static rows classified as legacy_mirror_only_file_missing.",
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
        from scytaledroid.Database.db_utils.artifact_registry_static_prune import (
            apply_static_prune,
            build_static_prune_proposal,
            validate_static_prune_proposal,
            write_static_prune_receipts,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    included_reasons = ["truly_detached"]
    if args.include_legacy_mirror_missing:
        included_reasons.append("legacy_mirror_only_file_missing")

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"artifact_registry_static_prune_{stamp}"

    try:
        proposal = build_static_prune_proposal(
            core_q.run_sql,
            repo_root=_REPO_ROOT,
            include_primary_reasons=included_reasons,
            expected_count=args.expected_count,
        )
        receipt_paths = write_static_prune_receipts(
            args.receipt_dir,
            stem=stem,
            proposal=proposal,
            apply_requested=bool(args.apply),
            apply_result=None,
        )

        summary = {
            "mode": "apply" if args.apply else "dry_run",
            "receipt_paths": receipt_paths,
            "included_primary_reasons": list(proposal.included_primary_reasons),
            "targeted_row_count": proposal.targeted_row_count,
            "targeted_distinct_static_run_ids": proposal.targeted_distinct_static_run_ids,
            "reason_counts": proposal.reason_counts,
            "total_artifact_registry_rows_before": proposal.total_rows_before,
            "static_dangling_rows_before": proposal.static_dangling_before,
            "dynamic_dangling_rows_before": proposal.dynamic_dangling_before,
            "all_missing_static_run": proposal.all_missing_static_run,
            "all_target_files_missing": proposal.all_target_files_missing,
            "all_missing_canonical_refs": proposal.all_missing_canonical_refs,
            "all_missing_legacy_runs_overlap": proposal.all_missing_legacy_runs_overlap,
            "canonical_db_residue_count": proposal.canonical_db_residue_count,
            "legacy_runs_overlap_count": proposal.legacy_runs_overlap_count,
            "host_file_present_count": proposal.host_file_present_count,
            "expected_count_match": proposal.expected_count_match,
        }
        validation_error: str | None = None
        try:
            validate_static_prune_proposal(proposal, expected_count=args.expected_count)
        except ValueError as exc:
            validation_error = str(exc)
            summary["validation_error"] = validation_error

        if args.apply:
            if validation_error:
                raise ValueError(validation_error)
            if args.expected_count is None:
                raise ValueError("static apply requires --expected-count for safety")
            with database_session() as db:
                with db.transaction():
                    proposal_txn = build_static_prune_proposal(
                        core_q.run_sql,
                        repo_root=_REPO_ROOT,
                        include_primary_reasons=included_reasons,
                        expected_count=args.expected_count,
                    )
                    validate_static_prune_proposal(proposal_txn, expected_count=args.expected_count)
                    apply_result = apply_static_prune(
                        core_q.run_sql,
                        core_q.run_sql_rowcount,
                        proposal=proposal_txn,
                    )
                summary.update(
                    {
                        "deleted_count": apply_result.deleted_count,
                        "total_artifact_registry_rows_after": apply_result.total_rows_after,
                        "static_dangling_rows_after": apply_result.static_dangling_after,
                        "dynamic_dangling_rows_after": apply_result.dynamic_dangling_after,
                    }
                )
            write_static_prune_receipts(
                args.receipt_dir,
                stem=stem,
                proposal=proposal,
                apply_requested=True,
                apply_result=apply_result,
            )

        if args.json:
            sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
            return 0

        print("# artifact_registry static prune")
        print(f"mode: {summary['mode']}")
        print(f"included_primary_reasons: {json.dumps(summary['included_primary_reasons'])}")
        print(f"targeted_row_count: {summary['targeted_row_count']}")
        print(f"targeted_distinct_static_run_ids: {summary['targeted_distinct_static_run_ids']}")
        print(f"reason_counts: {json.dumps(summary['reason_counts'], sort_keys=True)}")
        print(f"total_artifact_registry_rows_before: {summary['total_artifact_registry_rows_before']}")
        print(f"static_dangling_rows_before: {summary['static_dangling_rows_before']}")
        if args.apply:
            print(f"deleted_count: {summary['deleted_count']}")
            print(f"total_artifact_registry_rows_after: {summary['total_artifact_registry_rows_after']}")
            print(f"static_dangling_rows_after: {summary['static_dangling_rows_after']}")
        print("receipt files:")
        for key, value in sorted(receipt_paths.items()):
            print(f"  {key}: {value}")
        if not args.apply:
            print("dry-run only")
        return 0
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"static prune failed: {type(exc).__name__}: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
