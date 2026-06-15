#!/usr/bin/env python3
"""Refresh repo-owned external SDK / tracker intel from the Exodus public API."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, date, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_DEFAULT_OUTPUT_DIR = _REPO_ROOT / "data" / "state" / "external_sdk_tracker_intel"


def _parse_date(value: str) -> date:
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO date: {value}") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-url",
        default="https://reports.exodus-privacy.eu.org/api/trackers",
        help="Source endpoint to fetch (default: %(default)s).",
    )
    parser.add_argument(
        "--snapshot-date",
        type=_parse_date,
        default=None,
        help="Override snapshot date (YYYY-MM-DD). Default is today UTC.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_DEFAULT_OUTPUT_DIR,
        help=f"Receipt directory (default: {_DEFAULT_OUTPUT_DIR}).",
    )
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: %(default)s).")
    parser.add_argument("--write-bundle", action="store_true", help="Write JSON/CSV/text receipt bundle.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary.")
    parser.add_argument("--apply", action="store_true", help="Write normalized rows into MariaDB.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    fetched_at = datetime.now(UTC)
    try:
        from scytaledroid.Database.db_utils.external_sdk_tracker_intel import (
            build_refresh_summary,
            ensure_external_tracker_intel_schema,
            fetch_exodus_trackers,
            load_external_tracker_snapshot_counts,
            normalize_exodus_trackers,
            upsert_external_tracker_rows,
            write_refresh_receipt_bundle,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    try:
        payload = fetch_exodus_trackers(args.source_url, timeout=max(int(args.timeout), 1))
        rows = normalize_exodus_trackers(
            payload,
            fetched_at_utc=fetched_at,
            snapshot_date=args.snapshot_date,
            source_url=args.source_url,
        )
    except Exception as exc:  # noqa: BLE001 - operator-facing boundary
        sys.stderr.write(f"Fetch failed: {exc}\n")
        return 2

    snapshot_before: dict[str, int] = {"total_rows": 0, "distinct_trackers": 0}
    snapshot_after: dict[str, int] = {"total_rows": 0, "distinct_trackers": 0}
    if args.apply:
        try:
            from scytaledroid.Database.db_core import db_config
            from scytaledroid.Database.db_core import db_queries as core_q
            from scytaledroid.Database.db_core.db_engine import DatabaseError
            from scytaledroid.Database.db_core.session import database_session
        except ImportError as exc:
            sys.stderr.write(f"Database imports failed: {exc}\n")
            return 1
        if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
            sys.stderr.write("Database is disabled in db_config.\n")
            return 2
        try:
            with database_session() as db:
                with db.transaction():
                    ensure_external_tracker_intel_schema(core_q.run_sql)
                    snapshot_before = load_external_tracker_snapshot_counts(
                        core_q.run_sql,
                        snapshot_date=str(rows[0]["snapshot_date"]) if rows else fetched_at.date().isoformat(),
                    )
                    upsert_external_tracker_rows(core_q.run_sql, rows)
                    snapshot_after = load_external_tracker_snapshot_counts(
                        core_q.run_sql,
                        snapshot_date=str(rows[0]["snapshot_date"]) if rows else fetched_at.date().isoformat(),
                    )
        except DatabaseError as exc:
            sys.stderr.write(f"Database error: {exc}\n")
            return 2
        except Exception as exc:  # noqa: BLE001 - operator-facing boundary
            sys.stderr.write(f"Refresh failed: {exc}\n")
            return 2

    summary = build_refresh_summary(
        rows=rows,
        snapshot_before=snapshot_before,
        snapshot_after=snapshot_after,
        applied=args.apply,
        source_url=args.source_url,
    )

    receipt_files: dict[str, str] = {}
    if args.write_bundle:
        stamp = fetched_at.strftime("%Y%m%dT%H%M%SZ")
        stem = f"external_sdk_tracker_intel_refresh_{stamp}"
        receipt_files = write_refresh_receipt_bundle(
            summary=summary,
            rows=rows,
            output_dir=Path(args.output_dir),
            stem=stem,
        )
        summary["receipt_files"] = receipt_files

    if args.json:
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        return 0

    print("# external sdk tracker intel refresh")
    print(f"applied: {summary['applied']}")
    print(f"snapshot_date: {summary['snapshot_date']}")
    print(f"row_count: {summary['row_count']}")
    print(f"distinct_tracker_ids: {summary['distinct_tracker_ids']}")
    print(f"rows_with_code_signature: {summary['rows_with_code_signature']}")
    print(f"rows_with_network_signature: {summary['rows_with_network_signature']}")
    print(f"rows_with_website: {summary['rows_with_website']}")
    print(f"snapshot_rows_before: {summary['snapshot_rows_before']}")
    print(f"snapshot_rows_after: {summary['snapshot_rows_after']}")
    print(f"snapshot_new_rows_estimate: {summary['snapshot_new_rows_estimate']}")
    if receipt_files:
        print(f"receipt_json: {receipt_files.get('json')}")
    if not args.apply:
        print("dry-run only (no DB writes). Re-run with --apply to upsert rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
