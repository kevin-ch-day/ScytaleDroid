#!/usr/bin/env python3
"""Replay canonical static persistence from a saved report JSON (dry-run or live).

Uses the same entrypoint as production: ``persist_run_summary`` → transactional
stage writers (findings, permission matrix + storage, metrics/sections, handoff).

Examples::

  # Safe: exercises envelope + findings prep + dry-run branch (no DB writes)
  PYTHONPATH=. python scripts/static_analysis/replay_persist_run_summary.py \\
    --report data/static_analysis/reports/latest/<sha>.json

  # Live: requires a fresh session_stamp for the package (immutable session rule)
  PYTHONPATH=. python scripts/static_analysis/replay_persist_run_summary.py \\
    --report ... --live --session-stamp replay-$(date -u +%Y%m%d-%H%M%S)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def _outcome_dict(o: object) -> dict[str, object]:
    return {
        "success": bool(getattr(o, "success", False)),
        "run_id": getattr(o, "run_id", None),
        "static_run_id": getattr(o, "static_run_id", None),
        "runtime_findings": getattr(o, "runtime_findings", None),
        "persisted_findings": getattr(o, "persisted_findings", None),
        "string_samples_persisted": getattr(o, "string_samples_persisted", None),
        "persistence_failed": getattr(o, "persistence_failed", None),
        "persistence_transaction_state": getattr(o, "persistence_transaction_state", None),
        "persistence_failure_stage": getattr(o, "persistence_failure_stage", None),
        "persistence_warnings": list(getattr(o, "persistence_warnings", []) or []),
        "errors": list(getattr(o, "errors", []) or []),
        "persistence_exception_class": getattr(o, "persistence_exception_class", None),
        "persistence_exception_message": getattr(o, "persistence_exception_message", None),
        "persistence_sql_errno": getattr(o, "persistence_sql_errno", None),
        "persistence_failing_table": getattr(o, "persistence_failing_table", None),
        "static_handoff_hash": getattr(o, "static_handoff_hash", None),
        "persistence_retry_count": getattr(o, "persistence_retry_count", None),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        required=True,
        type=Path,
        help="Path to static analysis report JSON.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Perform real DB writes (default is dry-run: no transaction commits).",
    )
    parser.add_argument(
        "--session-stamp",
        default=None,
        help="Override session_stamp (else from report metadata if present).",
    )
    parser.add_argument(
        "--scope-label",
        default=None,
        help="Scope label for persistence (else metadata or 'persistence-replay').",
    )
    parser.add_argument(
        "--static-run-id",
        type=int,
        default=None,
        help="Optional existing static_run_id (skips session/package disambiguation block).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON only.",
    )
    args = parser.parse_args()
    dry_run = not args.live

    from scytaledroid.StaticAnalysis.cli.persistence.run_summary import persist_run_summary
    from scytaledroid.StaticAnalysis.cli.views.renderers.summary_render import render_app_result
    from scytaledroid.StaticAnalysis.persistence.reports import load_report

    report = load_report(args.report.resolve())
    manifest = report.manifest
    package = (manifest.package_name or "").strip()
    if not package:
        print("Report manifest.package_name missing; cannot replay.", file=sys.stderr)
        return 2

    meta = dict(report.metadata) if isinstance(report.metadata, dict) else {}
    session_stamp = (args.session_stamp or meta.get("session_stamp") or "").strip()
    if not session_stamp:
        print(
            "Missing session_stamp (use --session-stamp or set metadata.session_stamp on the report).",
            file=sys.stderr,
        )
        return 2

    scope_label = (args.scope_label or meta.get("scope_label") or "persistence-replay").strip()
    if not scope_label:
        scope_label = "persistence-replay"

    # ``render_app_result`` normalises string analysis; counts must be a mapping (not None).
    string_data: dict[str, object] = {"counts": {}, "samples": {}}
    _, payload, finding_totals = render_app_result(
        report,
        signer=None,
        split_count=1,
        string_data=string_data,
        duration_seconds=0.0,
        verbose_output=False,
    )
    totals_map = dict(finding_totals) if isinstance(finding_totals, Counter) else dict(finding_totals)

    stages = [
        "prepare_run_envelope",
        "execute_persistence_transaction:bootstrap_persistence_transaction",
        "execute_persistence_transaction:persist_findings_and_correlations_stage",
        "execute_persistence_transaction:persist_permission_and_storage_stage",
        "execute_persistence_transaction:persist_metrics_and_sections_stage",
        "execute_persistence_transaction:finalize_static_handoff_stage (post-commit)",
        "finalize_persisted_static_run",
    ]

    outcome = persist_run_summary(
        report,
        string_data,
        package,
        session_stamp=session_stamp,
        scope_label=scope_label,
        finding_totals=totals_map,
        baseline_payload=payload,
        static_run_id=args.static_run_id,
        run_status="COMPLETED",
        dry_run=dry_run,
    )

    txn_state = getattr(outcome, "persistence_transaction_state", None)
    if dry_run:
        rolled_back: bool | None = None
        committed: bool | None = None
    else:
        rolled_back = str(txn_state or "").lower() == "rolled_back"
        committed = str(txn_state or "").lower() == "committed"

    block: dict[str, object] = {
        "package": package,
        "report": str(args.report.resolve()),
        "session_stamp": session_stamp,
        "scope_label": scope_label,
        "dry_run": dry_run,
        "production_equivalent_stages": stages,
        "outcome": _outcome_dict(outcome),
        "rollback": rolled_back,
        "transaction_committed": committed,
    }

    if args.json:
        print(json.dumps(block, indent=2, default=str))
    else:
        print(json.dumps(block, indent=2, default=str))
        print()
        print(
            "Notes: dry-run skips execute_persistence_transaction and DB commits "
            "(rollback/transaction_committed are null). "
            "String samples may be empty unless string_data is populated separately."
        )
    return 0 if outcome.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
