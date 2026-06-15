#!/usr/bin/env python3
"""Refresh an existing static persistence-audit JSON summary from live DB + filesystem truth."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _resolve_path(session: str, output_dir: str) -> Path | None:
    stamp = (session or "").strip()
    if not stamp:
        return None
    base = Path(output_dir) / "audit" / "persistence"
    for suffix in ("persistence_audit", "missing_run_ids"):
        candidate = base / f"{stamp}_{suffix}.json"
        if candidate.is_file():
            return candidate
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refresh the summary block of an existing persistence-audit JSON artifact.",
    )
    parser.add_argument(
        "--session",
        help="Session stamp to resolve under output/audit/persistence.",
    )
    parser.add_argument(
        "--path",
        help="Explicit persistence-audit JSON path.",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Output root used when resolving --session (default: output).",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write the refreshed payload back to disk. Default is dry-run summary only.",
    )
    args = parser.parse_args()

    if not args.session and not args.path:
        parser.error("one of --session or --path is required")
    if args.session and args.path:
        parser.error("use only one of --session or --path")

    path = Path(args.path) if args.path else _resolve_path(args.session, args.output_dir)
    if path is None or not path.is_file():
        sys.stderr.write("Persistence audit artifact not found.\n")
        return 1

    from scytaledroid.StaticAnalysis.cli.flows.run_persistence_audit import (
        refresh_persistence_audit_artifact,
    )

    refreshed = refresh_persistence_audit_artifact(path, write=args.write)
    reports = (
        refreshed.get("summary", {}).get("reports", {})
        if isinstance(refreshed.get("summary"), dict)
        else {}
    )
    print(json.dumps(
        {
            "path": str(path),
            "write": bool(args.write),
            "session_stamp": refreshed.get("session_stamp"),
            "archive_json_paths": reports.get("archive_json_paths"),
            "latest_json_paths": reports.get("latest_json_paths"),
            "recorded_archive_json_paths": reports.get("recorded_archive_json_paths"),
            "summary_refreshed_at_utc": refreshed.get("summary_refreshed_at_utc"),
        },
        indent=2,
        sort_keys=True,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
