#!/usr/bin/env python3
"""Backfill capture identity metadata into historical dynamic PCAP artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.pcap.identity import (  # noqa: E402
    ensure_features_capture_identity,
    ensure_report_capture_identity,
)


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default="output/evidence/dynamic",
        help="Dynamic evidence root to inspect.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Maximum run directories to inspect.")
    parser.add_argument("--apply", action="store_true", help="Write missing identity fields in place.")
    return parser


def main() -> int:
    args = _parser().parse_args()
    root = Path(args.root)
    run_dirs = sorted(p for p in root.iterdir() if p.is_dir()) if root.exists() else []
    if args.limit is not None:
        run_dirs = run_dirs[: max(0, int(args.limit))]

    scanned = 0
    report_exists = 0
    features_exists = 0
    report_changed = 0
    features_changed = 0
    errors: list[str] = []

    for run_dir in run_dirs:
        manifest = _read_json(run_dir / "run_manifest.json")
        if not manifest:
            continue
        scanned += 1
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        package_name = str((target or {}).get("package_name") or "").strip() or None
        app_label = str(
            (target or {}).get("display_name")
            or (target or {}).get("app_label")
            or (target or {}).get("label")
            or ""
        ).strip() or None
        dynamic_run_id = str(manifest.get("dynamic_run_id") or run_dir.name).strip() or run_dir.name

        report_path = run_dir / "analysis" / "pcap_report.json"
        report = _read_json(report_path)
        if report is not None:
            report_exists += 1
            try:
                changed = ensure_report_capture_identity(
                    report,
                    dynamic_run_id=dynamic_run_id,
                    package_name=package_name,
                    app_label=app_label,
                )
                if changed:
                    report_changed += 1
                    if args.apply:
                        _write_json(report_path, report)
            except Exception as exc:
                errors.append(f"{run_dir.name}: report: {exc}")

        features_path = run_dir / "analysis" / "pcap_features.json"
        features = _read_json(features_path)
        if features is not None:
            features_exists += 1
            try:
                changed = ensure_features_capture_identity(
                    features,
                    dynamic_run_id=dynamic_run_id,
                    package_name=package_name,
                    app_label=app_label,
                    report=report,
                )
                if changed:
                    features_changed += 1
                    if args.apply:
                        _write_json(features_path, features)
            except Exception as exc:
                errors.append(f"{run_dir.name}: features: {exc}")

    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"Dynamic PCAP identity backfill ({mode})")
    print("----------------------------------")
    print(f"scanned           : {scanned}")
    print(f"report_exists     : {report_exists}")
    print(f"features_exists   : {features_exists}")
    print(f"report_changed    : {report_changed}")
    print(f"features_changed  : {features_changed}")
    if errors:
        print("errors            :")
        for error in errors[:20]:
            print(f"  - {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
