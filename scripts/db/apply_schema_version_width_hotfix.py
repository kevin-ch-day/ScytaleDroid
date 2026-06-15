#!/usr/bin/env python3
"""Apply the runtime schema_version width hotfix for base persistence tables."""

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
    parser.add_argument("--apply", action="store_true", help="Run the live ALTER/view-recreate migration.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.schema_version_width_hotfix import (
            apply_schema_version_width_hotfix,
            collect_schema_version_width_hotfix_preflight,
            required_alter_sql,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1
    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    preflight = collect_schema_version_width_hotfix_preflight(core_q.run_sql)
    planned_sql = required_alter_sql(core_q.run_sql)
    if not args.apply:
        payload = {
            "mode": "dry_run_only",
            "preflight_summary": preflight.get("summary") or {},
            "planned_statement_count": planned_sql.count("ALTER TABLE"),
            "planned_tables": sorted(
                {
                    str(row["table"])
                    for row in (preflight.get("columns") or [])
                    if str(row.get("needs_width_change") or "").strip().lower() == "yes"
                }
            ),
        }
        if args.json:
            sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        else:
            print("# schema-version width hotfix apply gate")
            print(f"preflight_clean: {payload['preflight_summary'].get('preflight_clean')}")
            print(f"planned_statement_count: {payload['planned_statement_count']}")
        return 0

    result = apply_schema_version_width_hotfix(core_q.run_sql)
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
        print("# schema-version width hotfix apply")
        print(f"applied: {payload['applied']}")
        print(f"altered_column_count: {payload['altered_column_count']}")
        print(f"receipt_path: {payload['receipt_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
