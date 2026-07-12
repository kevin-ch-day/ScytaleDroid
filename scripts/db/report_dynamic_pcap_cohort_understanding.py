#!/usr/bin/env python3
"""Synthesize PCAP understanding across all dynamic evidence packs (filesystem-first)."""

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
    parser.add_argument("--evidence-root", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--stdout-json", action="store_true")
    return parser


def _default_evidence_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_pcap_cohort_understanding" / stamp


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

    from scytaledroid.DynamicAnalysis.pcap.cohort_understanding import (
        build_cohort_understanding,
        render_cohort_understanding_md,
    )

    summary = build_cohort_understanding(evidence_root)
    per_run_rows = [row.__dict__ for row in summary.rows]
    review_md = render_cohort_understanding_md(summary)

    per_run_path = output_dir / "per_run_understanding.csv"
    app_path = output_dir / "app_understanding_rollup.csv"
    review_path = output_dir / "cohort_pcap_understanding.md"
    summary_path = output_dir / "summary.json"

    run_fields = list(per_run_rows[0].keys()) if per_run_rows else ["run_id", "package_name"]
    app_fields = list(summary.app_rollups[0].keys()) if summary.app_rollups else ["package", "app_label"]
    _write_csv(per_run_path, per_run_rows, run_fields)
    _write_csv(app_path, summary.app_rollups, app_fields)
    review_path.write_text(review_md, encoding="utf-8")

    payload = summary.to_dict()
    payload["output_files"] = {
        "per_run_understanding_csv": str(per_run_path.resolve()),
        "app_understanding_rollup_csv": str(app_path.resolve()),
        "cohort_pcap_understanding_md": str(review_path.resolve()),
        "summary_json": str(summary_path.resolve()),
    }
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.stdout_json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        print("# cohort PCAP understanding")
        print(f"runs_scanned     : {summary.runs_scanned}")
        print(f"valid_runs       : {summary.valid_runs}")
        print(f"surface_ok       : {summary.runs_with_surface}")
        print(f"pcap_total_gb    : {summary.total_pcap_bytes / (1024**3):.2f}")
        print(f"xmpp_runs        : {summary.xmpp_runs}")
        print(f"denied_observed  : {summary.denied_but_observed}")
        print(f"tls_alert_runs   : {summary.tls_alert_runs}")
        print(f"review           : {review_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
