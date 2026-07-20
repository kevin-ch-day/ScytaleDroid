#!/usr/bin/env python3
"""Apply and seed DB-backed dynamic service/provider context tables."""

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
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary.")
    parser.add_argument("--apply", action="store_true", help="Apply migration and seed rows.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_core.session import database_session
        from scytaledroid.Database.db_utils.dynamic_service_context import (
            apply_dynamic_service_context_migration,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    if not args.apply:
        summary = {"dry_run": True, "message": "Re-run with --apply to create/seed dynamic service context tables."}
    else:
        try:
            with database_session() as db:
                with db.transaction():
                    summary = apply_dynamic_service_context_migration(core_q.run_sql)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Apply failed: {exc}\n")
            return 2

    if args.json:
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    print("# dynamic service context")
    for key in ("migration_id", "schema_version_after", "services_seeded", "domain_maps_seeded", "service_rows_after", "domain_map_rows_after"):
        if key in summary:
            print(f"{key}: {summary.get(key)}")
    if summary.get("dry_run"):
        print(summary.get("message"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
