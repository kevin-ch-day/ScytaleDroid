#!/usr/bin/env python3
"""Read-only Phase A preflight for schema type normalization."""

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
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "data" / "state" / "schema_migrations",
        help="Write preflight receipts here.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.type_normalization_preflight import (
            collect_type_normalization_preflight,
            write_type_normalization_preflight_bundle,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1
    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"phase_a_type_normalization_preflight_{stamp}"
    report = collect_type_normalization_preflight(core_q.run_sql)
    files = write_type_normalization_preflight_bundle(report, args.output_dir, stem=stem)
    payload = {
        "summary": report["summary"],
        "receipt_files": files,
        "sql_companion": "scripts/db/sql/report_type_normalization_preflight.sql",
    }
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return 0
    print("# type normalization preflight")
    print(f"preflight_clean: {payload['summary']['preflight_clean']}")
    print(f"receipt_json: {files['json']}")
    print("sql_companion: scripts/db/sql/report_type_normalization_preflight.sql")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
