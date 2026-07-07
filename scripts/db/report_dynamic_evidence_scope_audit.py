#!/usr/bin/env python3
"""Report dynamic evidence scope labels for scenario-window vs full-PCAP captures."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--package", dest="packages", action="append", default=[])
    parser.add_argument("--run-id", dest="run_ids", action="append", default=[])
    parser.add_argument("--include-invalid", action="store_true")
    parser.add_argument("--no-segment-probe", action="store_true")
    parser.add_argument("--max-segment-probes", type=int, default=25)
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--stdout-json", action="store_true")
    return parser


def _default_evidence_root() -> Path:
    from scytaledroid.Config import app_config

    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_evidence_scope" / stamp


def _active_cohort_packages() -> set[str]:
    try:
        from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_packages

        return {str(pkg).strip().lower() for pkg in active_research_cohort_packages() if str(pkg).strip()}
    except Exception:
        return set()


def _write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _print_console(payload: dict, rows: list[dict], output_files: dict[str, str]) -> None:
    print("# dynamic evidence scope audit")
    print(f"runs_scanned     : {payload['runs_scanned']}")
    for label, count in payload["classification_counts"].items():
        print(f"{label.lower():17}: {count}")
    if payload["missing_metric_counts"]:
        missing = ", ".join(f"{key}={value}" for key, value in payload["missing_metric_counts"].items())
        print(f"missing_metrics  : {missing}")
    print()
    print("Worst duration mismatch")
    _print_rows(payload["top_duration_mismatch"])
    print()
    print("Worst PCAP/netstats ratio")
    _print_rows(payload["top_ratio_outliers"])
    print()
    print("Largest pre-scenario byte share")
    _print_rows(payload["top_pre_scenario_byte_share"])
    print()
    print("Review rows")
    review_rows = [row for row in rows if row.get("scope_classification") != "SCOPE_CLEAN"]
    _print_review_rows(review_rows[:12])
    print()
    print(f"csv              : {output_files['csv']}")
    print(f"json             : {output_files['json']}")


def _print_rows(rows: list[dict]) -> None:
    if not rows:
        print("  (none)")
        return
    for row in rows:
        metric_keys = [key for key in row if key not in {"dynamic_run_id", "package_name", "app_label", "scope_classification"}]
        metric = metric_keys[0] if metric_keys else "metric"
        print(
            "  "
            f"{str(row.get('app_label') or row.get('package_name') or '')[:18]:18} "
            f"{str(row.get('dynamic_run_id') or '')[:8]:8} "
            f"{row.get('scope_classification'):<30} "
            f"{metric}={row.get(metric)}"
        )


def _print_review_rows(rows: list[dict]) -> None:
    if not rows:
        print("  (none)")
        return
    for row in rows:
        print(
            "  "
            f"{str(row.get('app_label') or row.get('package_name') or '')[:18]:18} "
            f"{str(row.get('dynamic_run_id') or '')[:8]:8} "
            f"{row.get('scope_classification'):<30} "
            f"delta={row.get('duration_delta_s')} "
            f"ratio={row.get('pcap_to_netstats_ratio')} "
            f"pre_share={row.get('pre_scenario_byte_share')} "
            f"{row.get('scope_reasons') or ''}"
        )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    evidence_root = Path(args.evidence_root) if args.evidence_root else _default_evidence_root()
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    packages = {str(pkg).strip().lower() for pkg in args.packages if str(pkg).strip()}
    run_ids = {str(run_id).strip().lower() for run_id in args.run_ids if str(run_id).strip()}
    if not packages and not run_ids:
        packages = _active_cohort_packages()

    from scytaledroid.DynamicAnalysis.services.evidence_scope_audit import build_evidence_scope_audit

    audit = build_evidence_scope_audit(
        evidence_root,
        packages=packages or None,
        run_ids=run_ids or None,
        include_invalid=args.include_invalid,
        segment_probe=not args.no_segment_probe,
        max_segment_probes=max(args.max_segment_probes, 0),
        top_n=max(args.top, 1),
    )
    rows = [asdict(row) for row in audit.rows]
    csv_path = output_dir / "dynamic_evidence_scope_audit.csv"
    json_path = output_dir / "dynamic_evidence_scope_audit.json"
    fieldnames = list(rows[0].keys()) if rows else ["dynamic_run_id", "package_name", "scope_classification"]
    _write_csv(csv_path, rows, fieldnames)

    payload = audit.to_dict()
    payload["package_filter"] = sorted(packages)
    payload["run_id_filter"] = sorted(run_ids)
    payload["segment_probe_enabled"] = not args.no_segment_probe
    payload["output_files"] = {"csv": str(csv_path.resolve()), "json": str(json_path.resolve())}
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.stdout_json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        _print_console(payload, rows, payload["output_files"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
