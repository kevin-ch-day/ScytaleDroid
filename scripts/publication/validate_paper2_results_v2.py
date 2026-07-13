#!/usr/bin/env python3
"""Independently validate the Paper 2 v2 runtime-ML results package."""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any

DEFAULT_OUTPUT_ROOT = Path("output/_internal/publication/paper2_v2")
TOLERANCE = 1e-12


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Paper 2 v2 results using an independent aggregation pass.")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="Paper 2 v2 output root.")
    parser.add_argument("--write", action="store_true", help="Write manifest/paper2_independent_validation_v2.json.")
    args = parser.parse_args(argv)

    output_root = Path(args.output_root)
    result = validate(output_root)
    if args.write:
        out = output_root / "manifest" / "paper2_independent_validation_v2.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(out)
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "OK" else 1


def validate(output_root: Path) -> dict[str, Any]:
    results_path = output_root / "publication_results_v2.json"
    per_app_path = output_root / "paper2_per_app_rdi_v2.csv"
    sensitivity_path = output_root / "paper2_run_sensitivity_v2.csv"
    for path in (results_path, per_app_path, sensitivity_path):
        if not path.exists():
            raise FileNotFoundError(path)

    publication_results = _read_json(results_path)
    freeze_path = Path(str(publication_results["freeze_path"]))
    evidence_root = Path(str(publication_results["evidence_root"]))
    freeze = _read_json(freeze_path)

    recomputed = _recompute_app_rdi(freeze, evidence_root)
    generated_rows = {row["package_name"]: row for row in _read_csv(per_app_path)}
    app_mismatches = _compare_per_app(recomputed, generated_rows)

    deltas = [row["if_delta_rdi"] for row in recomputed.values()]
    paired = _paired_wilcoxon(deltas)
    sensitivity_rows = _read_csv(sensitivity_path)
    primary_row = next(
        (
            row
            for row in sensitivity_rows
            if row.get("model") == "iforest" and row.get("aggregation_policy") == "pooled_window_weighted"
        ),
        {},
    )
    stat_mismatches = _compare_primary_statistics(paired, primary_row)

    status = "OK" if not app_mismatches and not stat_mismatches else "FAIL"
    return {
        "schema_version": "paper2_independent_validation_v2",
        "status": status,
        "tolerance": TOLERANCE,
        "input_files": {
            "publication_results_v2": str(results_path),
            "paper2_per_app_rdi_v2": str(per_app_path),
            "paper2_run_sensitivity_v2": str(sensitivity_path),
            "freeze_path": str(freeze_path),
            "evidence_root": str(evidence_root),
        },
        "verification_scope": {
            "selected_run_ids": "reads from publication_results_v2 -> freeze_path and validates generated per-app rows against freeze run IDs",
            "selected_build_groups": "not independently reselected; relies on locked freeze",
            "feature_rows": "not independently rebuilt from PCAP features",
            "thresholds": "not independently recalibrated; uses persisted is_anomalous flags in score CSVs",
            "model_training": "not independently retrained",
            "score_direction": "not independently verified beyond using persisted is_anomalous flags",
            "per_run_rdi": "implicitly recomputed by summing per-window anomaly flags by run phase",
            "per_app_aggregation": "independently recomputed for pooled/window-weighted Isolation Forest RDI",
            "wilcoxon": "independently recomputed from full-precision per-app deltas",
            "source_hashes": "not independently verified against hash manifest",
        },
        "recomputed": {
            "apps": len(recomputed),
            "baseline_windows": sum(int(row["baseline_windows"]) for row in recomputed.values()),
            "interactive_windows": sum(int(row["interactive_windows"]) for row in recomputed.values()),
            "positive_differences": paired["positive_differences"],
            "negative_differences": paired["negative_differences"],
            "zero_differences": paired["zero_differences"],
            "wilcoxon_w_statistic": paired["wilcoxon_w_statistic"],
            "wilcoxon_p_value_two_sided_exact": paired["wilcoxon_p_value_two_sided_exact"],
        },
        "generated": {
            "apps": len(generated_rows),
            "primary_wilcoxon_w": primary_row.get("wilcoxon_w"),
            "primary_wilcoxon_p_two_sided": primary_row.get("wilcoxon_p_two_sided"),
        },
        "app_mismatches": app_mismatches,
        "statistic_mismatches": stat_mismatches,
    }


def _recompute_app_rdi(freeze: Mapping[str, Any], evidence_root: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for package_name, app in (freeze.get("apps") or {}).items():
        baseline_ids = [str(run_id) for run_id in app.get("baseline_run_ids") or []]
        interactive_ids = [str(run_id) for run_id in app.get("interactive_run_ids") or []]
        baseline_anom, baseline_windows = _sum_scores(evidence_root, baseline_ids)
        interactive_anom, interactive_windows = _sum_scores(evidence_root, interactive_ids)
        if baseline_windows <= 0 or interactive_windows <= 0:
            continue
        baseline_rdi = baseline_anom / baseline_windows
        interactive_rdi = interactive_anom / interactive_windows
        rows[str(package_name)] = {
            "package_name": str(package_name),
            "if_baseline_rdi": baseline_rdi,
            "if_interactive_rdi": interactive_rdi,
            "if_delta_rdi": interactive_rdi - baseline_rdi,
            "baseline_windows": baseline_windows,
            "interactive_windows": interactive_windows,
            "baseline_runs": len(baseline_ids),
            "interactive_runs": len(interactive_ids),
        }
    return rows


def _sum_scores(evidence_root: Path, run_ids: list[str]) -> tuple[int, int]:
    anomalous = 0
    windows = 0
    for run_id in run_ids:
        path = evidence_root / run_id / "analysis" / "ml" / "v1" / "anomaly_scores_iforest.csv"
        with path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                windows += 1
                if _truthy(row.get("is_anomalous") or row.get("is_exceedance")):
                    anomalous += 1
    return anomalous, windows


def _compare_per_app(
    recomputed: Mapping[str, Mapping[str, Any]],
    generated_rows: Mapping[str, Mapping[str, str]],
) -> list[dict[str, Any]]:
    mismatches: list[dict[str, Any]] = []
    for package_name, expected in sorted(recomputed.items()):
        generated = generated_rows.get(package_name)
        if not generated:
            mismatches.append({"package_name": package_name, "field": "row", "expected": "present", "actual": "missing"})
            continue
        for field in ("if_baseline_rdi", "if_interactive_rdi", "if_delta_rdi"):
            actual = _float(generated.get(field))
            if not _close(float(expected[field]), actual):
                mismatches.append(
                    {
                        "package_name": package_name,
                        "field": field,
                        "expected": expected[field],
                        "actual": actual,
                    }
                )
        for field in ("baseline_windows", "interactive_windows", "baseline_runs", "interactive_runs"):
            actual_int = int(float(generated.get(field) or 0))
            if int(expected[field]) != actual_int:
                mismatches.append(
                    {
                        "package_name": package_name,
                        "field": field,
                        "expected": int(expected[field]),
                        "actual": actual_int,
                    }
                )
    for package_name in sorted(set(generated_rows) - set(recomputed)):
        mismatches.append({"package_name": package_name, "field": "row", "expected": "absent", "actual": "present"})
    return mismatches


def _paired_wilcoxon(deltas: list[float]) -> dict[str, Any]:
    from scipy import stats

    values = [float(delta) for delta in deltas if math.isfinite(float(delta))]
    nonzero = [value for value in values if value != 0]
    result = stats.wilcoxon(nonzero, alternative="two-sided", zero_method="wilcox", method="exact")
    return {
        "n_pairs": len(values),
        "positive_differences": sum(1 for value in values if value > 0),
        "negative_differences": sum(1 for value in values if value < 0),
        "zero_differences": sum(1 for value in values if value == 0),
        "wilcoxon_w_statistic": float(result.statistic),
        "wilcoxon_p_value_two_sided_exact": float(result.pvalue),
    }


def _compare_primary_statistics(paired: Mapping[str, Any], primary_row: Mapping[str, str]) -> list[dict[str, Any]]:
    checks = {
        "positive_differences": float(paired["positive_differences"]),
        "negative_differences": float(paired["negative_differences"]),
        "zero_differences": float(paired["zero_differences"]),
        "wilcoxon_w": float(paired["wilcoxon_w_statistic"]),
        "wilcoxon_p_two_sided": float(paired["wilcoxon_p_value_two_sided_exact"]),
    }
    mismatches: list[dict[str, Any]] = []
    for field, expected in checks.items():
        actual = _float(primary_row.get(field))
        if not _close(expected, actual):
            mismatches.append({"field": field, "expected": expected, "actual": actual})
    return mismatches


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _float(value: Any) -> float:
    return float(value) if value not in (None, "") else float("nan")


def _close(expected: float, actual: float) -> bool:
    return math.isclose(expected, actual, rel_tol=0, abs_tol=TOLERANCE)


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
