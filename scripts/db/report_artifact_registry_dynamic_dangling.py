#!/usr/bin/env python3
"""Read-only audit of dangling dynamic ``artifact_registry`` rows.

Discovers the live dynamic schema, correlates dangling registry rows against
dynamic DB surfaces and local files, and writes a CSV/JSON audit bundle.

Examples:

  PYTHONPATH=. python scripts/db/report_artifact_registry_dynamic_dangling.py
  PYTHONPATH=. python scripts/db/report_artifact_registry_dynamic_dangling.py --verbose
  PYTHONPATH=. python scripts/db/report_artifact_registry_dynamic_dangling.py --output-dir /tmp/dynamic-dangling-audit
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _bundle_report_cli import (
    bootstrap_repo_root,
    check_db_enabled,
    default_output_dir,
    load_core_db,
    summarize_bundle,
)

_REPO_ROOT = bootstrap_repo_root(__file__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/artifact_registry_dynamic_dangling/<stamp>/.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the summary JSON to stdout after writing files.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print compact progress to stderr.",
    )
    return parser


def _log(verbose: bool, message: str) -> None:
    if verbose:
        sys.stderr.write(f"{message}\n")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        db_config, core_q = load_core_db()
        if check_db_enabled(db_config, "DB disabled; dynamic dangling audit needs the core database."):
            return 2
        from scytaledroid.Database.db_utils.artifact_registry_dynamic_dangling import (
            collect_artifact_registry_dynamic_dangling_report,
            write_artifact_registry_dynamic_dangling_bundle,
        )

        output_dir = Path(args.output_dir) if args.output_dir else default_output_dir(_REPO_ROOT, "artifact_registry_dynamic_dangling")
        _log(args.verbose, "collecting dynamic dangling registry audit")
        report = collect_artifact_registry_dynamic_dangling_report(core_q.run_sql, repo_root=_REPO_ROOT)
        files = write_artifact_registry_dynamic_dangling_bundle(report, output_dir)
        summary = summarize_bundle(report, files, output_dir)
        (output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )

        if args.json:
            sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
            return 0

        reason_flags = summary.get("reason_flag_counts") or {}
        primary_counts = summary.get("primary_reason_counts") or {}
        print("# artifact_registry dynamic dangling audit (read-only)")
        print(f"output_dir: {output_dir}")
        print(f"dangling_dynamic_registry_rows: {summary.get('dangling_dynamic_registry_rows')}")
        print(f"linked_dynamic_registry_rows: {summary.get('linked_dynamic_registry_rows')}")
        print(f"distinct_dynamic_run_count: {summary.get('distinct_dynamic_run_count')}")
        print(f"primary_reason_counts: {json.dumps(primary_counts, sort_keys=True)}")
        print(f"reason_flag_counts: {json.dumps(reason_flags, sort_keys=True)}")
        print(f"schema_tables_discovered: {', '.join(summary.get('schema_tables_discovered') or [])}")
        print("sql_companion: scripts/db/sql/audit_artifact_registry_dynamic_dangling.sql")
        return 0
    except Exception as exc:  # noqa: BLE001 - operator-facing audit script
        sys.stderr.write(f"dynamic dangling audit failed: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
