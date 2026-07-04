#!/usr/bin/env python3
"""Cohort PCAP security analysis from cached security_surface artifacts (no tshark)."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", default=None, help="Dynamic evidence root.")
    parser.add_argument("--output-dir", default=None, help="Audit output directory.")
    parser.add_argument("--run-id", action="append", default=[], help="Restrict to run id(s).")
    parser.add_argument(
        "--refresh-derived",
        action="store_true",
        help="Rehydrate findings/review/features/overlap from cached security_surface.json before analysis.",
    )
    parser.add_argument("--apply-refresh", action="store_true", help="With --refresh-derived, write refreshed artifacts.")
    parser.add_argument("--stdout-json", action="store_true", help="Print summary JSON.")
    return parser


def _default_evidence_root() -> Path:
    from scytaledroid.Config import app_config

    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_pcap_security_cohort" / stamp


def _write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    evidence_root = Path(args.evidence_root) if args.evidence_root else _default_evidence_root()
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    from scytaledroid.DynamicAnalysis.pcap.security_cohort import (
        analyze_security_cohort,
        build_app_security_rollup,
        generate_cohort_security_report,
        render_cohort_security_review_md,
    )

    if args.refresh_derived:
        payload = generate_cohort_security_report(
            evidence_root=evidence_root,
            output_dir=output_dir,
            run_ids=tuple(args.run_id),
            refresh_derived=True,
            apply_refresh=bool(args.apply_refresh),
        )
    else:
        summary = analyze_security_cohort(evidence_root, run_ids=tuple(args.run_id))
        per_run_rows = [row.__dict__ for row in summary.rows]
        app_rows = build_app_security_rollup(summary.rows)
        review_md = render_cohort_security_review_md(summary)
        per_run_path = output_dir / "per_run_security.csv"
        app_path = output_dir / "app_security_rollup.csv"
        review_path = output_dir / "cohort_security_review.md"
        summary_path = output_dir / "summary.json"
        run_fields = list(per_run_rows[0].keys()) if per_run_rows else ["run_id", "package_name"]
        app_fields = list(app_rows[0].keys()) if app_rows else ["package", "app_label"]
        _write_csv(per_run_path, per_run_rows, run_fields)
        _write_csv(app_path, app_rows, app_fields)
        review_path.write_text(review_md, encoding="utf-8")
        payload = summary.to_dict()
        payload["refresh_derived"] = False
        payload["refresh_stats"] = {"ok": 0, "skipped": 0}
        payload["output_files"] = {
            "per_run_security_csv": str(per_run_path.resolve()),
            "app_security_rollup_csv": str(app_path.resolve()),
            "cohort_security_review_md": str(review_path.resolve()),
            "summary_json": str(summary_path.resolve()),
        }
        summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.stdout_json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        print("# dynamic PCAP security cohort")
        print(f"runs_scanned          : {payload.get('runs_scanned')}")
        print(f"surface_ok            : {payload.get('surface_ok')}")
        print(f"cleartext_surface     : {payload.get('cleartext_surface_runs')}")
        print(f"http_metadata         : {payload.get('http_metadata_runs')}")
        print(f"xmpp_cleartext        : {payload.get('xmpp_cleartext_runs')}")
        print(f"denied_but_observed   : {payload.get('mismatch_denied_observed')}")
        if args.refresh_derived:
            stats = payload.get("refresh_stats") or {}
            print(f"refresh_ok            : {stats.get('ok', 0)}")
            print(f"refresh_skipped       : {stats.get('skipped', 0)}")
        files = payload.get("output_files") or {}
        if files.get("cohort_security_review_md"):
            print(f"cohort_review         : {files['cohort_security_review_md']}")
        if files.get("app_security_rollup_csv"):
            print(f"app_rollup            : {files['app_security_rollup_csv']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
