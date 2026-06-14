#!/usr/bin/env python3
"""Backfill typed ``artifact_registry`` linkage columns without deleting rows.

Default mode is read-only: print before/after-style audit counts and planned
backfill targets. Pass ``--apply`` to perform the UPDATE statements.

Run from repo root::

  PYTHONPATH=. python scripts/db/backfill_artifact_registry_typed_linkage.py
  PYTHONPATH=. python scripts/db/backfill_artifact_registry_typed_linkage.py --apply
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
    parser.add_argument("--apply", action="store_true", help="Perform UPDATE backfill statements.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.artifact_registry_typed_linkage import (
            backfill_artifact_registry_typed_linkage,
            collect_artifact_registry_typed_linkage_audit,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    try:
        before = collect_artifact_registry_typed_linkage_audit(core_q.run_sql)
        result = backfill_artifact_registry_typed_linkage(
            core_q.run_sql_rowcount,
            apply=bool(args.apply),
        )
        after = collect_artifact_registry_typed_linkage_audit(core_q.run_sql)
    except Exception as exc:
        sys.stderr.write(f"Typed linkage backfill failed: {exc}\n")
        return 2

    payload = {
        "applied": bool(result.applied),
        "static_rows_updated": int(result.static_rows_updated),
        "dynamic_rows_updated": int(result.dynamic_rows_updated),
        "before": before,
        "after": after,
        "sql_companion": "scripts/db/sql/audit_artifact_registry_typed_linkage.sql",
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print(f"apply: {payload['applied']}")
        print(f"static rows updated: {payload['static_rows_updated']}")
        print(f"dynamic rows updated: {payload['dynamic_rows_updated']}")
        print(f"fallback-needed rows before: {int(before.get('fallback_needed_rows') or 0)}")
        print(f"fallback-needed rows after : {int(after.get('fallback_needed_rows') or 0)}")
        print("audit companion: scripts/db/sql/audit_artifact_registry_typed_linkage.sql")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
