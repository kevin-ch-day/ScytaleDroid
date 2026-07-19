#!/usr/bin/env python3
"""Write a read-only Paper 3 historical-alignment versus freeze reconciliation."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alignment-manifest", required=True, help="Historical alignment analysis_manifest.json.")
    parser.add_argument("--freeze-manifest", required=True, help="Candidate paper_freeze_manifest.json.")
    parser.add_argument("--evidence-root", default="data/evidence/dynamic", help="Dynamic evidence root.")
    parser.add_argument("--output-dir", required=True, help="Destination for authority_audit.json and run_membership.csv.")
    parser.add_argument("--json", action="store_true", help="Print the summary JSON after writing outputs.")
    return parser


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from scytaledroid.Publication.paper3_authority import build_paper3_authority_audit

    report = build_paper3_authority_audit(
        alignment_manifest_path=Path(args.alignment_manifest),
        freeze_manifest_path=Path(args.freeze_manifest),
        evidence_root=Path(args.evidence_root),
    )
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "authority_audit.json"
    csv_path = output_dir / "run_membership.csv"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_csv(csv_path, list(report["runs"]))
    if args.json:
        print(json.dumps(report["summary"], indent=2, sort_keys=True))
    else:
        print(f"authority_audit.json: {json_path}")
        print(f"run_membership.csv: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
