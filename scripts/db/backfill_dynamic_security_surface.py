#!/usr/bin/env python3
"""Backfill security_surface.json and security_review.md for dynamic evidence packs.

Dry-run by default. With --apply, updates each pack's pcap_report.security_surface,
writes analysis/security_surface.json + analysis/security_review.md, and optionally
refreshes pcap_features.json and static_dynamic_overlap.json.
"""

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
    parser.add_argument("--evidence-root", default=None, help="Dynamic evidence root (default: data/evidence/dynamic).")
    parser.add_argument("--output-dir", default=None, help="Directory for cohort summary JSON receipt.")
    parser.add_argument("--run-id", action="append", default=[], help="Restrict to one or more dynamic run IDs.")
    parser.add_argument("--timeout", type=int, default=45, help="Per-run tshark timeout in seconds.")
    parser.add_argument("--apply", action="store_true", help="Write security artifacts and refresh derived outputs.")
    parser.add_argument(
        "--no-refresh-derived",
        action="store_true",
        help="With --apply, skip pcap_features + static_dynamic_overlap refresh.",
    )
    parser.add_argument("--stdout-json", action="store_true", help="Print summary JSON to stdout.")
    return parser


def _default_evidence_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_security_surface_backfill" / stamp


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    evidence_root = Path(args.evidence_root) if args.evidence_root else _default_evidence_root()
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()

    from scytaledroid.DynamicAnalysis.pcap.security_backfill import backfill_security_surface_cohort

    summary = backfill_security_surface_cohort(
        evidence_root,
        apply=bool(args.apply),
        refresh_derived=not bool(args.no_refresh_derived),
        run_ids=tuple(args.run_id),
        timeout_s=max(5, int(args.timeout)),
    )
    payload = summary.to_dict()
    payload["dry_run"] = not bool(args.apply)

    output_dir.mkdir(parents=True, exist_ok=True)
    receipt = output_dir / "summary.json"
    receipt.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.stdout_json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        mode = "APPLY" if args.apply else "DRY-RUN"
        print(f"# dynamic security surface backfill [{mode}]")
        print(f"evidence_root : {evidence_root}")
        print(f"scanned       : {summary.scanned}")
        print(f"ok            : {summary.ok}")
        print(f"skipped       : {summary.skipped}")
        print(f"failed        : {summary.failed}")
        print(f"cleartext_http: {summary.cleartext_http_runs}")
        print(f"cleartext_surface: {summary.cleartext_surface_runs}")
        print(f"denied_observed: {summary.mismatch_denied_observed}")
        print(f"allowed_not_observed: {summary.mismatch_allowed_not_observed}")
        if summary.skip_reasons:
            print("skip_reasons  :")
            for reason, count in sorted(summary.skip_reasons.items()):
                print(f"  - {reason}: {count}")
        print(f"receipt       : {receipt}")
        if not args.apply:
            print("Re-run with --apply to write security_surface artifacts.")

    return 0 if summary.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
