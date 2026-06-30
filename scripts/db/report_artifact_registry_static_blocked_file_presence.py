#!/usr/bin/env python3
"""Read-only file-presence correlation for blocked static legacy-overlap sessions."""

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
        help="Write outputs to this directory instead of output/audit/artifact_registry_static_blocked_file_presence/<stamp>/.",
    )
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout after writing files.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        db_config, core_q = load_core_db()
        if check_db_enabled(db_config, "DB disabled; blocked file presence report needs the core database."):
            return 2
        from scytaledroid.Database.db_utils.artifact_registry_static_blocked_file_presence import (
            collect_static_blocked_file_presence_report,
            write_static_blocked_file_presence_bundle,
        )

        output_dir = Path(args.output_dir) if args.output_dir else default_output_dir(_REPO_ROOT, "artifact_registry_static_blocked_file_presence")
        report = collect_static_blocked_file_presence_report(core_q.run_sql, repo_root=_REPO_ROOT)
        files = write_static_blocked_file_presence_bundle(report, output_dir)
        summary = summarize_bundle(report, files, output_dir)

        if args.json:
            sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
            return 0

        print("# artifact_registry static blocked file presence (read-only)")
        print(f"output_dir: {output_dir}")
        print(f"blocked_session_count: {summary.get('blocked_session_count')}")
        print(f"blocked_file_present_row_count: {summary.get('blocked_file_present_row_count')}")
        print(f"blocked_sessions: {json.dumps(summary.get('blocked_sessions') or [])}")
        return 0
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"blocked file presence report failed: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
