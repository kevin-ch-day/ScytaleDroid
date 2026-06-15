#!/usr/bin/env python3
"""Read-only report over schema migration governance state."""

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
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument(
        "--write-bundle",
        action="store_true",
        help="Write JSON/CSV/text receipt files under data/state/schema_migrations/.",
    )
    parser.add_argument(
        "--output-dir",
        default="data/state/schema_migrations",
        help="Directory for --write-bundle outputs (default: %(default)s).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.schema_migration_registry import (
            build_schema_migration_report,
            write_schema_migration_report_bundle,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    payload = build_schema_migration_report(core_q.run_sql)
    bundle_files: dict[str, str] = {}
    if args.write_bundle:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        stem = f"schema_migration_report_{stamp}"
        bundle_files = write_schema_migration_report_bundle(payload, Path(args.output_dir), stem=stem)
        payload["receipt_files"] = bundle_files

    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    print("# schema migrations")
    summary = payload.get("summary") or {}
    print(f"live_schema_version: {summary.get('live_schema_version') or 'unknown'}")
    print(f"registered_migration_count: {summary.get('registered_migration_count')}")
    print(f"applied_row_count: {summary.get('applied_row_count')}")
    print(
        "missing_migrations: "
        + (", ".join(payload.get("missing_migrations") or []) if payload.get("missing_migrations") else "(none)")
    )
    print(f"duplicate_registry_ids: {json.dumps(payload.get('duplicate_registry_ids') or {}, sort_keys=True)}")
    print(
        "duplicate_applied_migration_ids: "
        + json.dumps(payload.get("duplicate_applied_migration_ids") or {}, sort_keys=True)
    )
    print(
        "migration_retry_histories: "
        + json.dumps(payload.get("migration_retry_histories") or {}, sort_keys=True)
    )
    print(f"registry_chain_issue_count: {summary.get('registry_chain_issue_count')}")
    print(f"checksum_mismatch_count: {summary.get('checksum_mismatch_count')}")
    print(f"unregistered_applied_row_count: {summary.get('unregistered_applied_row_count')}")
    print(f"applied_status_counts: {json.dumps(summary.get('applied_status_counts') or {}, sort_keys=True)}")
    if bundle_files:
        print(f"receipt_json: {bundle_files.get('json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
