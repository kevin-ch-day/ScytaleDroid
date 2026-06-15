#!/usr/bin/env python3
"""Read-only preflight and planned SQL bundle for the runtime schema_version width hotfix."""

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
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=_REPO_ROOT / "data" / "state" / "schema_migrations" / "schema_version_width_hotfix",
        help="Write JSON/CSV/SQL preflight receipts here.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.schema_version_width_hotfix import (
            collect_schema_version_width_hotfix_preflight,
            write_schema_version_width_hotfix_preflight_bundle,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1
    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    report = collect_schema_version_width_hotfix_preflight(core_q.run_sql)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"schema_version_width_hotfix_{stamp}"
    files = write_schema_version_width_hotfix_preflight_bundle(report, args.receipt_dir, stem=stem)
    payload = {
        "summary": report.get("summary") or {},
        "receipt_files": files,
    }
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    summary = payload["summary"]
    print("# schema-version width hotfix preflight")
    print(f"target_column_count: {summary.get('target_column_count')}")
    print(f"live_schema_version: {summary.get('live_schema_version')}")
    print(f"live_schema_version_length: {summary.get('live_schema_version_length')}")
    print(f"hotfix_schema_version_after: {summary.get('hotfix_schema_version_after')}")
    print(f"hotfix_schema_version_after_length: {summary.get('hotfix_schema_version_after_length')}")
    print(f"max_current_stored_schema_version_length: {summary.get('max_current_stored_schema_version_length')}")
    print(f"values_gt_64_total: {summary.get('values_gt_64_total')}")
    print(f"views_requiring_recreate_count: {summary.get('views_requiring_recreate_count')}")
    print(f"required_alter_statement_count: {summary.get('required_alter_statement_count')}")
    print(f"preflight_clean: {summary.get('preflight_clean')}")
    print(f"receipt_json: {files.get('json')}")
    print(f"planned_sql: {files.get('planned_sql')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
