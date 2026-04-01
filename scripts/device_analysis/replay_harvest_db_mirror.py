#!/usr/bin/env python3
"""Replay harvest DB mirror rows from authoritative package manifests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.replay import (
    find_package_manifests,
    load_package_manifest,
    replay_manifests,
)


def _default_root() -> Path:
    return (Path(app_config.DATA_DIR) / "device_apks").resolve()


def _summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {
        "packages_total": len(results),
        "replayed": 0,
        "partial": 0,
        "failed": 0,
        "skipped": 0,
        "artifacts_replayed": 0,
        "artifacts_failed": 0,
        "artifacts_skipped": 0,
    }
    for row in results:
        status = str(row.get("status") or "")
        if status in summary:
            summary[status] += 1
        summary["artifacts_replayed"] += int(row.get("replayed_artifacts") or 0)
        summary["artifacts_failed"] += int(row.get("failed_artifacts") or 0)
        summary["artifacts_skipped"] += int(row.get("skipped_artifacts") or 0)
    return summary


def _dry_run_candidates(root: Path, *, session_label: str | None, package_names: set[str] | None, limit: int | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen = 0
    for manifest_path in find_package_manifests(root):
        payload = load_package_manifest(manifest_path)
        package = dict(payload.get("package") or {})
        status = dict(payload.get("status") or {})
        package_name = str(package.get("package_name") or "").strip()
        manifest_session = str(package.get("session_label") or "").strip() or None
        if session_label and manifest_session != session_label:
            continue
        if package_names and package_name not in package_names:
            continue
        seen += 1
        if limit is not None and seen > limit:
            break
        rows.append(
            {
                "manifest_path": str(manifest_path),
                "package_name": package_name,
                "session_label": manifest_session,
                "persistence_status": status.get("persistence_status"),
                "capture_status": status.get("capture_status"),
                "research_status": status.get("research_status"),
            }
        )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay harvest DB mirror rows from package manifests.")
    parser.add_argument("--root", type=Path, default=_default_root(), help="Root directory to search for harvest manifests.")
    parser.add_argument("--session", dest="session_label", help="Only replay manifests for this harvest session label.")
    parser.add_argument("--package", action="append", default=[], help="Replay only the given package name(s).")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of package manifests to process.")
    parser.add_argument("--force", action="store_true", help="Replay even when persistence_status is not mirror_failed.")
    parser.add_argument("--dry-run", action="store_true", help="Report matching manifests without writing DB rows.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    args = parser.parse_args(argv)

    package_names = {str(item).strip() for item in args.package if str(item).strip()} or None
    root = args.root.resolve()

    if args.dry_run:
        rows = _dry_run_candidates(
            root,
            session_label=args.session_label,
            package_names=package_names,
            limit=args.limit,
        )
        summary = {
            "packages_total": len(rows),
            "mirror_failed_candidates": sum(1 for row in rows if row.get("persistence_status") == "mirror_failed"),
        }
        payload = {"summary": summary, "packages": rows}
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        else:
            print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    results = replay_manifests(
        root,
        session_label=args.session_label,
        package_names=package_names,
        force=bool(args.force),
        limit=args.limit,
    )
    rows = [
        {
            "manifest_path": str(result.manifest_path),
            "package_name": result.package_name,
            "session_label": result.session_label,
            "previous_persistence_status": result.previous_persistence_status,
            "status": result.status,
            "replayed_artifacts": result.replayed_artifacts,
            "failed_artifacts": result.failed_artifacts,
            "skipped_artifacts": result.skipped_artifacts,
            "updated_manifest": result.updated_manifest,
            "failure_reasons": result.failure_reasons,
        }
        for result in results
    ]
    payload = {"summary": _summarize(rows), "packages": rows}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
