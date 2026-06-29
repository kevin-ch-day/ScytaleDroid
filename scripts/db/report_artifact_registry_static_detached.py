#!/usr/bin/env python3
"""Read-only report for detached static ``artifact_registry`` prune candidates.

Builds the same detached static proposal used by
``prune_artifact_registry_static_detached.py`` but never writes receipts and
never deletes rows. Use this as the safe inspection step before any prune.

Examples:

  PYTHONPATH=. python scripts/db/report_artifact_registry_static_detached.py
  PYTHONPATH=. python scripts/db/report_artifact_registry_static_detached.py --json
  PYTHONPATH=. python scripts/db/report_artifact_registry_static_detached.py --include-legacy-mirror-missing
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
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="Optional exact target count guard for read-only comparison.",
    )
    p.add_argument(
        "--include-legacy-mirror-missing",
        action="store_true",
        help="Also include rows classified as legacy_mirror_only_file_missing.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON to stdout.",
    )
    return p


def _build_payload(proposal) -> dict[str, object]:  # noqa: ANN001
    return {
        "report_type": "artifact_registry_static_detached_candidates",
        "included_primary_reasons": list(proposal.included_primary_reasons),
        "targeted_row_count": proposal.targeted_row_count,
        "targeted_distinct_static_run_ids": proposal.targeted_distinct_static_run_ids,
        "targeted_static_run_ids": list(proposal.targeted_static_run_ids),
        "reason_counts": proposal.reason_counts,
        "artifact_type_counts": proposal.artifact_type_counts,
        "path_family_counts": proposal.path_family_counts,
        "oldest_created_at_utc": proposal.oldest_created_at_utc,
        "newest_created_at_utc": proposal.newest_created_at_utc,
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
        "exact_sql_predicate": proposal.exact_sql_predicate,
        "sample_rows": list(proposal.sample_rows),
    }


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.artifact_registry_static_prune import (
            build_static_prune_proposal,
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

    try:
        proposal = build_static_prune_proposal(
            core_q.run_sql,
            repo_root=_REPO_ROOT,
            include_primary_reasons=included_reasons,
            expected_count=args.expected_count,
        )
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"static detached report failed: {type(exc).__name__}: {exc}\n")
        return 2

    payload = _build_payload(proposal)
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    print("# artifact_registry static detached candidates")
    print(f"included_primary_reasons: {json.dumps(payload['included_primary_reasons'])}")
    print(f"targeted_row_count: {payload['targeted_row_count']}")
    print(f"targeted_distinct_static_run_ids: {payload['targeted_distinct_static_run_ids']}")
    print(f"reason_counts: {json.dumps(payload['reason_counts'], sort_keys=True)}")
    print(f"artifact_type_counts: {json.dumps(payload['artifact_type_counts'], sort_keys=True)}")
    print(f"path_family_counts: {json.dumps(payload['path_family_counts'], sort_keys=True)}")
    print(f"oldest_created_at_utc: {payload['oldest_created_at_utc']}")
    print(f"newest_created_at_utc: {payload['newest_created_at_utc']}")
    print(f"total_artifact_registry_rows_before: {payload['total_artifact_registry_rows_before']}")
    print(f"static_dangling_rows_before: {payload['static_dangling_rows_before']}")
    print(f"dynamic_dangling_rows_before: {payload['dynamic_dangling_rows_before']}")
    print(f"all_missing_static_run: {payload['all_missing_static_run']}")
    print(f"all_target_files_missing: {payload['all_target_files_missing']}")
    print(f"all_missing_canonical_refs: {payload['all_missing_canonical_refs']}")
    print(f"all_missing_legacy_runs_overlap: {payload['all_missing_legacy_runs_overlap']}")
    print(f"canonical_db_residue_count: {payload['canonical_db_residue_count']}")
    print(f"legacy_runs_overlap_count: {payload['legacy_runs_overlap_count']}")
    print(f"host_file_present_count: {payload['host_file_present_count']}")
    if payload.get("expected_count_match") is not None:
        print(f"expected_count_match: {payload['expected_count_match']}")
    print("sample_rows:")
    for row in payload["sample_rows"]:
        print(f"  {json.dumps(row, sort_keys=True, default=str)}")
    print("read_only: true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
