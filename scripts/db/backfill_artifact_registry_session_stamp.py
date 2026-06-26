#!/usr/bin/env python3
"""Backfill static ``artifact_registry.session_stamp`` from canonical static runs.

Default mode is read-only: report the current gap and the planned backfill
counts. Pass ``--apply`` to add the column/indexes if needed and perform the
UPDATE statements.
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
    parser.add_argument("--apply", action="store_true", help="Perform the additive schema apply and UPDATE backfill.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.artifact_registry_session_stamp import (
            backfill_artifact_registry_session_stamp,
            collect_artifact_registry_session_stamp_audit,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    try:
        before = collect_artifact_registry_session_stamp_audit(core_q.run_sql)
        result = backfill_artifact_registry_session_stamp(
            core_q.run_sql,
            core_q.run_sql_rowcount,
            apply=bool(args.apply),
        )
        after = collect_artifact_registry_session_stamp_audit(core_q.run_sql)
    except Exception as exc:
        sys.stderr.write(f"artifact_registry session_stamp backfill failed: {exc}\n")
        return 2

    payload = {
        "applied": bool(result.applied),
        "ddl_applied": bool(result.ddl_applied),
        "typed_static_rows_updated": int(result.typed_static_rows_updated),
        "legacy_static_rows_updated": int(result.legacy_static_rows_updated),
        "before": before,
        "after": after,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print(f"apply: {payload['applied']}")
        print(f"ddl applied: {payload['ddl_applied']}")
        print(f"typed static rows updated: {payload['typed_static_rows_updated']}")
        print(f"legacy static rows updated: {payload['legacy_static_rows_updated']}")
        print(f"rows with session_stamp before: {int(before.get('rows_with_session_stamp') or 0)}")
        print(f"rows with session_stamp after : {int(after.get('rows_with_session_stamp') or 0)}")
        print(
            "static rows still missing session_stamp: "
            f"{int(after.get('typed_static_rows_missing_session_stamp') or 0) + int(after.get('legacy_static_rows_missing_session_stamp') or 0)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
