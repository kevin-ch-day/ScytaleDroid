#!/usr/bin/env python3
"""Receipt-first prune for candidate static legacy-overlap sessions.

Examples:
  PYTHONPATH=. python scripts/db/prune_artifact_registry_static_legacy_sessions.py \\
    --session-stamp 20260429-all-full --session-stamp 20260429-fcfk-full

  PYTHONPATH=. python scripts/db/prune_artifact_registry_static_legacy_sessions.py \\
    --session-stamp 20260429-all-full --session-stamp 20260429-fcfk-full \\
    --receipt-dir data/state/artifact_registry_static_session_prune --apply --expected-count 12
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--session-stamp",
        dest="session_stamps",
        action="append",
        required=True,
        help="Candidate legacy-overlap static session_stamp to target. Repeat for multiple sessions.",
    )
    parser.add_argument(
        "--receipt-dir",
        default=_REPO_ROOT / "data" / "state" / "artifact_registry_static_session_prune",
        help="Directory for JSON/CSV/SQL/txt receipts.",
    )
    parser.add_argument("--expected-count", type=int, default=None, help="Refuse apply if targeted row count differs.")
    parser.add_argument("--apply", action="store_true", help="Actually delete targeted artifact_registry rows.")
    parser.add_argument("--json", action="store_true", help="Print proposal/apply summary JSON.")
    return parser


def _load_db() -> tuple[Any, Any]:
    from scytaledroid.Database.db_core import db_config
    from scytaledroid.Database.db_core import db_queries as core_q

    return db_config, core_q


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        db_config, core_q = _load_db()
        if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
            sys.stderr.write("DB disabled; static legacy session prune needs the core database.\n")
            return 2
        from scytaledroid.Database.db_core.session import database_session
        from scytaledroid.Database.db_utils.artifact_registry_static_session_prune import (
            apply_static_session_prune,
            build_static_session_prune_proposal,
            validate_static_session_prune_proposal,
            write_static_session_prune_receipts,
        )

        receipt_dir = Path(args.receipt_dir)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        stem = f"artifact_registry_static_session_prune_{stamp}"
        proposal = build_static_session_prune_proposal(
            core_q.run_sql,
            repo_root=_REPO_ROOT,
            session_stamps=args.session_stamps,
            expected_count=args.expected_count,
        )
        receipt_paths = write_static_session_prune_receipts(
            receipt_dir,
            stem=stem,
            proposal=proposal,
            apply_requested=False,
        )
        payload: dict[str, Any] = {
            "targeted_row_count": proposal.targeted_row_count,
            "targeted_session_count": proposal.targeted_session_count,
            "targeted_run_count": proposal.targeted_run_count,
            "targeted_session_stamps": list(proposal.targeted_session_stamps),
            "candidate_actions": proposal.candidate_actions,
            "legacy_payload_total_rows": proposal.legacy_payload_total_rows,
            "file_present_count": proposal.file_present_count,
            "file_missing_count": proposal.file_missing_count,
            "canonical_db_residue_count": proposal.canonical_db_residue_count,
            "malformed_or_unknown_count": proposal.malformed_or_unknown_count,
            "receipt_paths": receipt_paths,
            "applied": False,
        }

        validation_error: str | None = None
        try:
            validate_static_session_prune_proposal(proposal, expected_count=args.expected_count)
        except ValueError as exc:
            validation_error = str(exc)
            payload["validation_error"] = validation_error

        if args.apply:
            if validation_error:
                raise ValueError(validation_error)
            with database_session(reuse_connection=False) as db:
                with db.transaction():
                    proposal_txn = build_static_session_prune_proposal(
                        core_q.run_sql,
                        repo_root=_REPO_ROOT,
                        session_stamps=args.session_stamps,
                        expected_count=args.expected_count,
                    )
                    validate_static_session_prune_proposal(proposal_txn, expected_count=args.expected_count)
                    apply_result = apply_static_session_prune(core_q.run_sql, core_q.run_sql_rowcount, proposal=proposal_txn)
                    if apply_result.deleted_count != proposal_txn.targeted_row_count:
                        raise RuntimeError(
                            f"deleted_count mismatch: expected {proposal_txn.targeted_row_count}, got {apply_result.deleted_count}"
                        )
            write_static_session_prune_receipts(
                receipt_dir,
                stem=stem,
                proposal=proposal_txn,
                apply_requested=True,
                apply_result=apply_result,
            )
            payload.update(
                {
                    "applied": True,
                    "deleted_count": apply_result.deleted_count,
                    "total_artifact_registry_rows_after": apply_result.total_rows_after,
                    "static_dangling_rows_after": apply_result.static_dangling_after,
                    "dynamic_dangling_rows_after": apply_result.dynamic_dangling_after,
                }
            )

        if args.json:
            sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
            return 0

        print("# artifact_registry static legacy session prune")
        print(f"targeted_session_stamps: {', '.join(proposal.targeted_session_stamps)}")
        print(f"targeted_row_count: {proposal.targeted_row_count}")
        print(f"targeted_run_count: {proposal.targeted_run_count}")
        print(f"receipt_json: {receipt_paths['json']}")
        if validation_error:
            print(f"validation_error: {validation_error}")
        if payload["applied"]:
            print(f"deleted_count: {payload['deleted_count']}")
            print(f"static_dangling_rows_after: {payload['static_dangling_rows_after']}")
        return 0
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"static legacy session prune failed: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
