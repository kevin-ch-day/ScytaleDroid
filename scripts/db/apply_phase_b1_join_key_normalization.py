#!/usr/bin/env python3
"""Apply Phase B1 join-key collation and width normalization after a clean dry-run."""

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
    parser.add_argument("--apply", action="store_true", help="Run the live B1 ALTER/view-recreate migration.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.phase_b1_join_key_normalization import (
            apply_phase_b1_join_key_normalization,
            build_required_alter_statements,
            collect_phase_b1_join_key_preflight,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1
    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    preflight = collect_phase_b1_join_key_preflight(core_q.run_sql)
    planned = build_required_alter_statements(core_q.run_sql)
    if not args.apply:
        payload = {
            "mode": "dry_run_only",
            "preflight_summary": preflight.get("summary") or {},
            "planned_statement_count": len(planned),
            "planned_tables": sorted({str(row['table']) for row in planned}),
        }
        if args.json:
            sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        else:
            print("# phase-b1 join-key normalization apply gate")
            print(f"preflight_clean: {payload['preflight_summary'].get('preflight_clean')}")
            print(f"planned_statement_count: {payload['planned_statement_count']}")
        return 0

    result = apply_phase_b1_join_key_normalization(core_q.run_sql)
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
        print("# phase-b1 join-key normalization apply")
        print(f"applied: {payload['applied']}")
        print(f"altered_column_count: {payload['altered_column_count']}")
        print(f"receipt_path: {payload['receipt_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
