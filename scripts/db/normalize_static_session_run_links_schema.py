#!/usr/bin/env python3
"""Normalize live ``static_session_run_links`` schema drift.

Default mode is read-only: report the current table-default/text-column/index/FK
drift. Pass ``--apply`` to run the bounded DDL migration.
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
    parser.add_argument("--apply", action="store_true", help="Perform the live static_session_run_links schema normalization.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.static_session_run_links_schema import (
            apply_static_session_run_links_schema_normalization,
            build_required_static_session_run_links_schema_statements,
            collect_static_session_run_links_schema_audit,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    try:
        before = collect_static_session_run_links_schema_audit(core_q.run_sql)
        if args.apply:
            result = apply_static_session_run_links_schema_normalization(core_q.run_sql)
            after = collect_static_session_run_links_schema_audit(core_q.run_sql)
            payload = {
                "mode": "apply",
                "applied": bool(result.applied),
                "statement_count": int(result.statement_count),
                "table_default_updated": bool(result.table_default_updated),
                "text_columns_updated": int(result.text_columns_updated),
                "index_added": bool(result.index_added),
                "foreign_key_added": bool(result.foreign_key_added),
                "receipt_path": result.receipt_path,
                "before": before,
                "after": after,
            }
        else:
            payload = {
                "mode": "dry_run_only",
                "before": before,
                "planned_statement_count": len(build_required_static_session_run_links_schema_statements(before)),
            }
    except Exception as exc:
        sys.stderr.write(f"static_session_run_links schema normalization failed: {exc}\n")
        return 2

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    if args.apply:
        print("# static_session_run_links schema normalization")
        print(f"applied: {payload['applied']}")
        print(f"statement_count: {payload['statement_count']}")
        print(f"table_default_updated: {payload['table_default_updated']}")
        print(f"text_columns_updated: {payload['text_columns_updated']}")
        print(f"index_added: {payload['index_added']}")
        print(f"foreign_key_added: {payload['foreign_key_added']}")
        print(f"receipt_path: {payload['receipt_path']}")
        return 0

    print("# static_session_run_links schema audit")
    print(f"table_default_collation: {before.get('table_default_collation')}")
    print(f"table_default_needs_change: {before.get('table_default_needs_change')}")
    print(f"text_columns_needing_normalization: {before.get('text_columns_needing_normalization')}")
    print(f"missing_origin_session_stamp_index: {before.get('missing_origin_session_stamp_index')}")
    print(f"missing_static_run_fk: {before.get('missing_static_run_fk')}")
    print(f"unlinked_static_run_rows: {before.get('unlinked_static_run_rows')}")
    print(f"apply_safe: {before.get('apply_safe')}")
    print(f"planned_statement_count: {payload.get('planned_statement_count')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
