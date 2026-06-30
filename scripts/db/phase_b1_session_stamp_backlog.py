#!/usr/bin/env python3
"""Phase B1 session-stamp backlog normalization preflight and apply entrypoint."""

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
    subparsers = parser.add_subparsers(dest="command", required=True)

    report = subparsers.add_parser("report", help="Run read-only preflight and write receipt files.")
    report.add_argument(
        "--receipt-dir",
        type=Path,
        default=_REPO_ROOT / "data" / "state" / "schema_migrations" / "phase_b1_session_stamp_backlog_normalization",
        help="Write JSON/CSV/SQL preflight receipts here.",
    )
    report.add_argument(
        "--sample-limit",
        type=int,
        default=20,
        help="Maximum duplicate-collision samples per target column.",
    )
    report.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary.")

    apply = subparsers.add_parser("apply", help="Show apply gate or run the live migration.")
    apply.add_argument(
        "--apply",
        action="store_true",
        help="Run the live ALTER/view-recreate migration.",
    )
    apply.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def _load_runtime_dependencies():
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.phase_b1_join_key_normalization import (
            apply_phase_b1_session_stamp_backlog_normalization,
            build_required_backlog_session_stamp_alter_statements,
            collect_phase_b1_session_stamp_backlog_preflight,
            write_phase_b1_session_stamp_backlog_preflight_bundle,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        raise SystemExit(1) from exc
    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        raise SystemExit(2)
    return (
        core_q,
        apply_phase_b1_session_stamp_backlog_normalization,
        build_required_backlog_session_stamp_alter_statements,
        collect_phase_b1_session_stamp_backlog_preflight,
        write_phase_b1_session_stamp_backlog_preflight_bundle,
    )


def _handle_report(args: argparse.Namespace) -> int:
    (
        core_q,
        _apply_phase_b1_session_stamp_backlog_normalization,
        _build_required_backlog_session_stamp_alter_statements,
        collect_phase_b1_session_stamp_backlog_preflight,
        write_phase_b1_session_stamp_backlog_preflight_bundle,
    ) = _load_runtime_dependencies()

    report = collect_phase_b1_session_stamp_backlog_preflight(
        core_q.run_sql,
        sample_limit=max(1, min(int(args.sample_limit), 100)),
    )
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"phase_b1_session_stamp_backlog_normalization_{stamp}"
    files = write_phase_b1_session_stamp_backlog_preflight_bundle(report, args.receipt_dir, stem=stem)
    payload = {
        "summary": report.get("summary") or {},
        "receipt_files": files,
    }
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    summary = payload["summary"]
    print("# phase-b1 session-stamp backlog preflight")
    print(f"target_column_count: {summary.get('target_column_count')}")
    print(f"duplicate_collision_count: {summary.get('duplicate_collision_count')}")
    print(f"width_violation_count: {summary.get('width_violation_count')}")
    print(f"duplicate_collapse_risk_zero: {summary.get('duplicate_collapse_risk_zero')}")
    print(f"width_safety_ok: {summary.get('width_safety_ok')}")
    print(f"views_requiring_recreate_count: {summary.get('views_requiring_recreate_count')}")
    print(f"join_parity_count: {summary.get('join_parity_count')}")
    print(f"preflight_clean: {summary.get('preflight_clean')}")
    print(f"receipt_json: {files.get('json')}")
    print(f"planned_sql: {files.get('planned_sql')}")
    return 0


def _handle_apply(args: argparse.Namespace) -> int:
    (
        core_q,
        apply_phase_b1_session_stamp_backlog_normalization,
        build_required_backlog_session_stamp_alter_statements,
        collect_phase_b1_session_stamp_backlog_preflight,
        _write_phase_b1_session_stamp_backlog_preflight_bundle,
    ) = _load_runtime_dependencies()

    preflight = collect_phase_b1_session_stamp_backlog_preflight(core_q.run_sql)
    planned = build_required_backlog_session_stamp_alter_statements(core_q.run_sql)
    if not args.apply:
        payload = {
            "mode": "dry_run_only",
            "preflight_summary": preflight.get("summary") or {},
            "planned_statement_count": len(planned),
            "planned_tables": sorted({str(row["table"]) for row in planned}),
        }
        if args.json:
            sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        else:
            print("# phase-b1 session-stamp backlog apply gate")
            print(f"preflight_clean: {payload['preflight_summary'].get('preflight_clean')}")
            print(f"planned_statement_count: {payload['planned_statement_count']}")
        return 0

    result = apply_phase_b1_session_stamp_backlog_normalization(core_q.run_sql)
    payload = {
        "mode": "apply",
        "applied": result.applied,
        "altered_column_count": result.altered_column_count,
        "altered_tables": list(result.altered_tables),
        "receipt_path": result.receipt_path,
    }
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    else:
        print("# phase-b1 session-stamp backlog apply")
        print(f"applied: {payload['applied']}")
        print(f"altered_column_count: {payload['altered_column_count']}")
        print(f"receipt_path: {payload['receipt_path']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "report":
        return _handle_report(args)
    return _handle_apply(args)


if __name__ == "__main__":
    raise SystemExit(main())
