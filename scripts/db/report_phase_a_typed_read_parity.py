#!/usr/bin/env python3
"""Read-only parity audit for Phase A typed replacement read paths."""

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
        default=_REPO_ROOT / "data" / "state" / "schema_migrations",
        help="Write JSON/CSV audit receipts here.",
    )
    parser.add_argument("--sample-limit", type=int, default=20, help="Maximum mismatch sample rows per section.")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.phase_a_read_parity import (
            collect_phase_a_read_parity,
            write_phase_a_read_parity_bundle,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1
    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    report = collect_phase_a_read_parity(core_q.run_sql, sample_limit=max(1, min(int(args.sample_limit), 200)))
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"phase_a_typed_read_parity_{stamp}"
    files = write_phase_a_read_parity_bundle(report, args.receipt_dir, stem=stem)
    payload = {
        "summary": report.get("summary") or {},
        "receipt_files": files,
    }
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    summary = payload["summary"]
    print("# phase-a typed read parity")
    print(f"parity_clean: {summary.get('parity_clean')}")
    print(f"live_schema_version: {summary.get('live_schema_version')}")
    print(f"dynamic_sessions_total: {summary.get('dynamic_sessions_total')}")
    print(f"static_link_state_mismatch_rows: {summary.get('static_link_state_mismatch_rows')}")
    print(f"started_at_parity_mismatch_rows: {summary.get('started_at_parity_mismatch_rows')}")
    print(f"dynamic_run_uuid_parity_mismatch_rows: {summary.get('dynamic_run_uuid_parity_mismatch_rows')}")
    print(f"receipt_json: {files.get('json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
