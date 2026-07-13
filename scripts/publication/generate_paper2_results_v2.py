#!/usr/bin/env python3
"""Generate the Paper 2 v2 locked runtime ML results package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--freeze",
        type=Path,
        default=None,
        help="Locked dataset freeze JSON. Defaults to the active research cohort freeze.",
    )
    parser.add_argument(
        "--dataset-plan",
        type=Path,
        default=_repo_root() / "data" / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_plan.json",
        help="Dataset plan JSON with per-run metadata.",
    )
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=_repo_root() / "data" / "evidence" / "dynamic",
        help="Dynamic evidence root containing per-run ML outputs.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=_repo_root() / "output" / "_internal" / "publication" / "paper2_v2",
        help="Output directory for the v2 results package.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = _repo_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from scytaledroid.Reporting.services.paper2_results_v2_service import generate_paper2_results_v2

    result = generate_paper2_results_v2(
        freeze_path=args.freeze,
        dataset_plan_path=args.dataset_plan,
        evidence_root=args.evidence_root,
        output_root=args.output_root,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
