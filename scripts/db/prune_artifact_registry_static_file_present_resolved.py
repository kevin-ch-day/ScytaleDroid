#!/usr/bin/env python3
"""Receipt-first registry cleanup for exact-hash file-present static rows.

Dry-run is the default. ``--apply`` requires ``--expected-count`` and deletes
only selected rows from ``artifact_registry``; it never deletes evidence files
or writes static/session tables.
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=_REPO_ROOT / "data" / "state" / "artifact_registry_static_file_present_resolution",
        help="Write timestamped JSON/CSV/SQL/run_id receipt bundle here.",
    )
    parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="Optional exact count guard; required for --apply.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete verified target rows after writing the receipt bundle.",
    )
    parser.add_argument("--json", action="store_true", help="Print proposal/apply summary JSON to stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_core.session import database_session
        from scytaledroid.Database.db_utils.artifact_registry_static_file_present_resolution import (
            apply_static_file_present_resolution,
            build_static_file_present_resolution_proposal,
            validate_static_file_present_resolution_proposal,
            write_static_file_present_resolution_receipts,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"artifact_registry_static_file_present_resolution_{stamp}"
    try:
        proposal = build_static_file_present_resolution_proposal(
            core_q.run_sql,
            repo_root=_REPO_ROOT,
            expected_count=args.expected_count,
        )
        receipt_paths = write_static_file_present_resolution_receipts(
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
            "targeted_distinct_static_run_ids": proposal.targeted_distinct_static_run_ids,
            "targeted_distinct_packages": proposal.targeted_distinct_packages,
            "staged_action": proposal.staged_action,
            "canonical_coverage_class": proposal.canonical_coverage_class,
            "artifact_type_counts": proposal.artifact_type_counts,
            "path_family_counts": proposal.path_family_counts,
            "total_artifact_registry_rows_before": proposal.total_rows_before,
            "static_dangling_rows_before": proposal.static_dangling_before,
            "all_host_files_present": proposal.all_host_files_present,
            "all_same_hash_covered": proposal.all_same_hash_covered,
            "all_have_canonical_match": proposal.all_have_canonical_match,
            "all_registry_resolution_candidates": proposal.all_registry_resolution_candidates,
            "expected_count_match": proposal.expected_count_match,
        }
        validation_error: str | None = None
        try:
            validate_static_file_present_resolution_proposal(proposal, expected_count=args.expected_count)
        except ValueError as exc:
            validation_error = str(exc)
            summary["validation_error"] = validation_error

        if args.apply:
            if args.expected_count is None:
                raise ValueError("static file-present apply requires --expected-count for safety")
            if validation_error:
                raise ValueError(validation_error)
            with database_session() as db:
                with db.transaction():
                    proposal_txn = build_static_file_present_resolution_proposal(
                        core_q.run_sql,
                        repo_root=_REPO_ROOT,
                        expected_count=args.expected_count,
                    )
                    validate_static_file_present_resolution_proposal(
                        proposal_txn,
                        expected_count=args.expected_count,
                    )
                    apply_result = apply_static_file_present_resolution(
                        core_q.run_sql,
                        core_q.run_sql_rowcount,
                        proposal=proposal_txn,
                    )
                summary.update(
                    {
                        "deleted_count": apply_result.deleted_count,
                        "total_artifact_registry_rows_after": apply_result.total_rows_after,
                        "static_dangling_rows_after": apply_result.static_dangling_after,
                    }
                )
            write_static_file_present_resolution_receipts(
                args.receipt_dir,
                stem=stem,
                proposal=proposal,
                apply_requested=True,
                apply_result=apply_result,
            )

        if args.json:
            sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
            return 0

        print("# artifact_registry static file-present resolution")
        print(f"mode: {summary['mode']}")
        print(f"targeted_row_count: {summary['targeted_row_count']}")
        print(f"targeted_distinct_static_run_ids: {summary['targeted_distinct_static_run_ids']}")
        print(f"targeted_distinct_packages: {summary['targeted_distinct_packages']}")
        print(f"staged_action: {summary['staged_action']}")
        print(f"canonical_coverage_class: {summary['canonical_coverage_class']}")
        print(f"artifact_type_counts: {json.dumps(summary['artifact_type_counts'], sort_keys=True)}")
        print(f"path_family_counts: {json.dumps(summary['path_family_counts'], sort_keys=True)}")
        print(f"total_artifact_registry_rows_before: {summary['total_artifact_registry_rows_before']}")
        print(f"static_dangling_rows_before: {summary['static_dangling_rows_before']}")
        if validation_error:
            print(f"validation_error: {validation_error}")
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
        sys.stderr.write(f"static file-present resolution failed: {type(exc).__name__}: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
