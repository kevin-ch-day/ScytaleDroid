#!/usr/bin/env python3
"""Generate minimum Paper 2 v2 scientific validation outputs.

Read-only with respect to evidence, DB rows, and the dataset freeze.  Outputs
are derived reporting artifacts under output/_internal/publication/paper2_v2.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, median, pstdev
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
from scipy import stats

from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as config
from scytaledroid.DynamicAnalysis.ml.anomaly_model_training import anomaly_scores, fit_model, fixed_model_specs
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import get_sampling_duration_seconds, load_run_inputs
from scytaledroid.DynamicAnalysis.ml.feature_matrix import BASIC_FEATURE_NAMES, rows_to_basic_matrix
from scytaledroid.DynamicAnalysis.ml.pcap_window_features import build_window_features, extract_packet_timeline
from scytaledroid.DynamicAnalysis.ml.telemetry_windowing import WindowSpec
from scytaledroid.Publication.app_category_policy import app_display_name
from scytaledroid.Publication.paper2_v2_contract import validate_paper2_v2_results_contract


DEFAULT_OUTPUT_ROOT = REPO_ROOT / "output" / "_internal" / "publication" / "paper2_v2"
DEFAULT_EVIDENCE_ROOT = REPO_ROOT / "data" / "evidence" / "dynamic"
DEFAULT_VALIDATION_DIR = DEFAULT_OUTPUT_ROOT / "minimum_validation"
SEEDS = [
    101,
    211,
    307,
    409,
    503,
    601,
    701,
    809,
    907,
    1009,
    1103,
    1201,
    1301,
    1409,
    1511,
    1601,
    1709,
    1801,
    1901,
    2003,
]


def _default_freeze_path() -> str:
    from scytaledroid.DynamicAnalysis.research_cohort_archive import resolve_dataset_freeze_read_path

    return str(resolve_dataset_freeze_read_path())


@dataclass(frozen=True)
class RunWindows:
    run_id: str
    package_name: str
    phase: str
    rows: list[dict[str, Any]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", default=None, help="Existing dataset freeze path.")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="Paper 2 v2 package root.")
    parser.add_argument("--evidence-root", default=str(DEFAULT_EVIDENCE_ROOT), help="Dynamic evidence root.")
    parser.add_argument("--out-dir", default=str(DEFAULT_VALIDATION_DIR), help="Validation output directory.")
    args = parser.parse_args(argv)

    result = generate(
        freeze_path=Path(args.freeze or _default_freeze_path()),
        output_root=Path(args.output_root),
        evidence_root=Path(args.evidence_root),
        out_dir=Path(args.out_dir),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "OK" else 1


def generate(*, freeze_path: Path, output_root: Path, evidence_root: Path, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    contract = validate_paper2_v2_results_contract(output_root, freeze_path=freeze_path)
    if not contract.ok:
        raise RuntimeError("Paper 2 v2 contract failed: " + "; ".join(contract.errors[:5]))

    freeze = _read_json(freeze_path)
    run_windows = _load_locked_run_windows(freeze=freeze, evidence_root=evidence_root)
    heldout_rows, heldout_app_rows = _heldout_baseline_validation(freeze, run_windows)
    heldout_deltas = {row["package_name"]: float(row["delta_mean"]) for row in heldout_app_rows}
    heldout_summary_rows = _summary_table("heldout_baseline", heldout_deltas)
    ablation_rows, ablation_app_rows = _feature_ablation(freeze, run_windows)
    bytes_rows, bytes_summary_rows = _bytes_p95_control(freeze, run_windows)
    temporal_rows, temporal_summary = _temporal_order_control(freeze, run_windows)
    seed_app_rows, seed_summary_rows = _seed_stability(freeze, run_windows)
    seed_cohort_rows = _seed_cohort_summary(seed_summary_rows)

    files = [
        _write_csv(out_dir / "heldout_baseline_folds_v2.csv", heldout_rows),
        _write_csv(out_dir / "heldout_baseline_by_app_v2.csv", heldout_app_rows),
        _write_csv(out_dir / "heldout_baseline_summary_v2.csv", heldout_summary_rows),
        _write_csv(out_dir / "feature_ablation_v2.csv", ablation_rows),
        _write_csv(out_dir / "feature_ablation_by_app_v2.csv", ablation_app_rows),
        _write_csv(out_dir / "bytes_p95_control_by_app_v2.csv", bytes_rows),
        _write_csv(out_dir / "bytes_p95_control_summary_v2.csv", bytes_summary_rows),
        _write_csv(out_dir / "seed_stability_by_app_v2.csv", seed_app_rows),
        _write_csv(out_dir / "seed_stability_by_seed_v2.csv", seed_summary_rows),
        _write_csv(out_dir / "seed_stability_summary_v2.csv", seed_cohort_rows),
        _write_csv(out_dir / "paper2_temporal_order_control_v2.csv", temporal_rows),
    ]
    temporal_json = out_dir / "paper2_temporal_order_control_v2.json"
    temporal_json.write_text(json.dumps(temporal_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files.append(temporal_json)
    files.append(
        _write_latex_summary(
            out_dir / "paper2_minimum_validation_tables_v2.tex",
            heldout_summary_rows,
            ablation_rows,
            bytes_summary_rows,
            seed_cohort_rows,
            temporal_rows,
        )
    )
    publication_results = _read_json(output_root / "publication_results_v2.json")
    deterministic_manifest = publication_results.get("deterministic_manifest") or {}
    summary = {
        "schema_version": "paper2_minimum_validation_v2",
        "status": "OK",
        "source_revision": _source_revision(),
        "freeze_path": str(freeze_path),
        "freeze_sha256": _sha256(freeze_path),
        "dataset_lock_sha256": deterministic_manifest.get("dataset_lock_sha256"),
        "included_run_set_hash": deterministic_manifest.get("included_run_set_hash"),
        "feature_contract_hash": deterministic_manifest.get("feature_contract_hash"),
        "model_parameter_hash": deterministic_manifest.get("model_parameter_hash"),
        "output_root": str(output_root),
        "out_dir": str(out_dir),
        "apps": len(freeze.get("apps") or {}),
        "runs": len(freeze.get("included_run_ids") or []),
        "heldout_eligible_apps": len({row["package_name"] for row in heldout_rows}),
        "heldout_fold_count": len(heldout_rows),
        "feature_ablation_profiles": len(ablation_rows),
        "seed_count": len(SEEDS),
        "bytes_control_positive_apps": bytes_summary_rows[0]["positive_differences"] if bytes_summary_rows else 0,
        "temporal_order_status": temporal_summary["status"],
        "generated_files": [str(path.relative_to(out_dir)) for path in files],
    }
    summary_path = out_dir / "summary.json"
    manifest_path = out_dir / "manifest.sha256.json"
    summary["manifest"] = str(manifest_path)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files.append(summary_path)
    _write_manifest(manifest_path, files, base_dir=out_dir)
    return summary


def _load_locked_run_windows(*, freeze: Mapping[str, Any], evidence_root: Path) -> dict[str, RunWindows]:
    out: dict[str, RunWindows] = {}
    spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)
    for package_name, app in sorted((freeze.get("apps") or {}).items()):
        if not isinstance(app, dict):
            continue
        run_phase: dict[str, str] = {}
        for run_id in app.get("baseline_run_ids") or []:
            run_phase[str(run_id)] = "baseline"
        for run_id in app.get("interactive_run_ids") or []:
            run_phase[str(run_id)] = "interactive"
        for run_id, phase in sorted(run_phase.items()):
            inputs = load_run_inputs(evidence_root / run_id)
            if not inputs or not inputs.pcap_path or not inputs.pcap_path.exists():
                raise RuntimeError(f"Missing PCAP inputs for locked run: {run_id}")
            duration = get_sampling_duration_seconds(inputs)
            if not duration:
                raise RuntimeError(f"Missing sampling duration for locked run: {run_id}")
            packets = extract_packet_timeline(inputs.pcap_path)
            rows, _dropped = build_window_features(
                packets,
                duration_s=float(duration),
                spec=spec,
            )
            out[run_id] = RunWindows(run_id=run_id, package_name=str(package_name), phase=phase, rows=rows)
    return out


def _heldout_baseline_validation(
    freeze: Mapping[str, Any], run_windows: Mapping[str, RunWindows]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    app_rows: list[dict[str, Any]] = []
    for package_name, app in sorted((freeze.get("apps") or {}).items()):
        meta = _app_meta(package_name, app)
        baseline_ids = [str(x) for x in app.get("baseline_run_ids") or []]
        interactive_ids = [str(x) for x in app.get("interactive_run_ids") or []]
        if len(baseline_ids) < 2:
            continue
        fold_values: list[float] = []
        interactive_values: list[float] = []
        for holdout in baseline_ids:
            train_ids = [run_id for run_id in baseline_ids if run_id != holdout]
            X_train = _matrix_for_runs(run_windows, train_ids, features=BASIC_FEATURE_NAMES)
            X_holdout = _matrix_for_runs(run_windows, [holdout], features=BASIC_FEATURE_NAMES)
            X_interactive = _matrix_for_runs(run_windows, interactive_ids, features=BASIC_FEATURE_NAMES)
            heldout_rdi, interactive_rdi = _fit_score_rdis(X_train, [X_holdout, X_interactive], seed=SEEDS[0])
            delta = interactive_rdi - heldout_rdi
            fold_values.append(heldout_rdi)
            interactive_values.append(interactive_rdi)
            rows.append(
                {
                    **meta,
                    "package_name": package_name,
                    "heldout_run_id": holdout,
                    "training_baseline_run_ids": ";".join(train_ids),
                    "baseline_run_count": len(baseline_ids),
                    "fold_count_for_app": len(baseline_ids),
                    "heldout_baseline_windows": int(X_holdout.shape[0]),
                    "interactive_windows": int(X_interactive.shape[0]),
                    "heldout_baseline_rdi": heldout_rdi,
                    "interactive_rdi": interactive_rdi,
                    "delta": delta,
                }
            )
        paired_deltas = [i - b for i, b in zip(interactive_values, fold_values, strict=True)]
        app_rows.append(
            {
                **meta,
                "package_name": package_name,
                "baseline_run_count": len(baseline_ids),
                "fold_count": len(fold_values),
                "heldout_baseline_rdi_mean": _mean(fold_values),
                "heldout_baseline_rdi_median": median(fold_values),
                "heldout_baseline_rdi_min": min(fold_values),
                "heldout_baseline_rdi_max": max(fold_values),
                "heldout_baseline_rdi_range": max(fold_values) - min(fold_values),
                "heldout_baseline_rdi_sd": _sd(fold_values),
                "interactive_rdi_mean": _mean(interactive_values),
                "interactive_rdi_median": median(interactive_values),
                "delta_mean": _mean(paired_deltas),
                "delta_median": median(paired_deltas),
                "delta_min": min(paired_deltas),
                "delta_max": max(paired_deltas),
                "delta_range": max(paired_deltas) - min(paired_deltas),
            }
        )
    return rows, app_rows


def _feature_ablation(
    freeze: Mapping[str, Any], run_windows: Mapping[str, RunWindows]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    profiles = [
        ("bytes_per_sec_only", ("bytes_per_sec",)),
        ("packets_per_sec_only", ("packets_per_sec",)),
        ("avg_packet_size_only", ("avg_packet_size_bytes",)),
        ("bytes_packets", ("bytes_per_sec", "packets_per_sec")),
        ("all_three", BASIC_FEATURE_NAMES),
    ]
    deltas_by_profile: dict[str, dict[str, float]] = {}
    rows: list[dict[str, Any]] = []
    app_rows: list[dict[str, Any]] = []
    for profile_name, features in profiles:
        app_values = _app_phase_values_for_features(freeze, run_windows, features=features, seed=SEEDS[0])
        deltas = {pkg: vals["delta"] for pkg, vals in app_values.items()}
        deltas_by_profile[profile_name] = deltas
        ranks = _rank_map(deltas)
        for package_name, vals in sorted(app_values.items()):
            app_rows.append(
                {
                    **_app_meta(package_name, (freeze.get("apps") or {}).get(package_name, {})),
                    "feature_profile": profile_name,
                    "features": ";".join(features),
                    "baseline_rdi": vals["baseline_rdi"],
                    "interactive_rdi": vals["interactive_rdi"],
                    "delta": vals["delta"],
                    "delta_rank": ranks[package_name],
                }
            )
        stats_row = _paired_summary(deltas.values())
        full_corr = ""
        if profile_name != "all_three":
            common = sorted(set(deltas) & set(deltas_by_profile.get("all_three", {})))
            if common:
                full_corr = stats.spearmanr(
                    [deltas[pkg] for pkg in common],
                    [deltas_by_profile["all_three"][pkg] for pkg in common],
                ).statistic
        rows.append(
            {
                "feature_profile": profile_name,
                "features": ";".join(features),
                "apps": len(deltas),
                **stats_row,
                "spearman_vs_full_model": full_corr,
                "app_ranking": ";".join(f"{pkg}:{ranks[pkg]}" for pkg in sorted(ranks, key=lambda p: ranks[p])),
                "per_app_delta_json": json.dumps(deltas, sort_keys=True),
            }
        )
    # Recompute correlations now that all_three is present.
    full = deltas_by_profile["all_three"]
    for row in rows:
        if row["feature_profile"] == "all_three":
            row["spearman_vs_full_model"] = 1.0
            continue
        deltas = deltas_by_profile[str(row["feature_profile"])]
        common = sorted(set(deltas) & set(full))
        row["spearman_vs_full_model"] = stats.spearmanr(
            [deltas[p] for p in common],
            [full[p] for p in common],
        ).statistic
    return rows, app_rows


def _bytes_p95_control(
    freeze: Mapping[str, Any], run_windows: Mapping[str, RunWindows]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    deltas: dict[str, float] = {}
    iforest_full = _app_phase_values_for_features(freeze, run_windows, features=BASIC_FEATURE_NAMES, seed=SEEDS[0])
    for package_name, app in sorted((freeze.get("apps") or {}).items()):
        baseline_ids = [str(x) for x in app.get("baseline_run_ids") or []]
        interactive_ids = [str(x) for x in app.get("interactive_run_ids") or []]
        baseline = _matrix_for_runs(run_windows, baseline_ids, features=("bytes_per_sec",)).reshape(-1)
        interactive = _matrix_for_runs(run_windows, interactive_ids, features=("bytes_per_sec",)).reshape(-1)
        threshold = float(np.percentile(baseline, config.THRESHOLD_PERCENTILE, method=config.NP_PERCENTILE_METHOD))
        baseline_rdi = float(np.mean(baseline >= threshold)) if baseline.size else 0.0
        interactive_rdi = float(np.mean(interactive >= threshold)) if interactive.size else 0.0
        delta = interactive_rdi - baseline_rdi
        deltas[str(package_name)] = delta
        full_delta = float(iforest_full[str(package_name)]["delta"])
        absolute_difference = abs(full_delta - delta)
        rows.append(
            {
                **_app_meta(package_name, app),
                "package_name": package_name,
                "baseline_windows": int(baseline.size),
                "interactive_windows": int(interactive.size),
                "baseline_p95_bytes_per_sec": threshold,
                "baseline_rdi": baseline_rdi,
                "interactive_rdi": interactive_rdi,
                "delta": delta,
                "iforest_delta": full_delta,
                "iforest_minus_bytes_delta": full_delta - delta,
                "absolute_delta_difference": absolute_difference,
                "comparison_class": _bytes_control_class(full_delta - delta),
            }
        )
    summary = _paired_summary(deltas.values())
    summary["feature_profile"] = "baseline_p95_bytes_per_sec"
    summary["spearman_vs_iforest_delta"] = stats.spearmanr(
        [deltas[pkg] for pkg in sorted(deltas)],
        [iforest_full[pkg]["delta"] for pkg in sorted(deltas)],
    ).statistic
    return rows, [summary]


def _seed_stability(
    freeze: Mapping[str, Any], run_windows: Mapping[str, RunWindows]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_app_seed: dict[str, list[float]] = {}
    by_app_baseline: dict[str, list[float]] = {}
    by_app_interactive: dict[str, list[float]] = {}
    seed_rows: list[dict[str, Any]] = []
    for seed in SEEDS:
        app_values = _app_phase_values_for_features(freeze, run_windows, features=BASIC_FEATURE_NAMES, seed=seed)
        deltas = {pkg: float(vals["delta"]) for pkg, vals in app_values.items()}
        for pkg, delta in deltas.items():
            by_app_seed.setdefault(pkg, []).append(delta)
            by_app_baseline.setdefault(pkg, []).append(float(app_values[pkg]["baseline_rdi"]))
            by_app_interactive.setdefault(pkg, []).append(float(app_values[pkg]["interactive_rdi"]))
        row = _paired_summary(deltas.values())
        row["seed"] = seed
        seed_rows.append(row)
    app_rows: list[dict[str, Any]] = []
    full_seed_ranks = {
        seed: _rank_map(
            {pkg: by_app_seed[pkg][i] for pkg in by_app_seed}
        )
        for i, seed in enumerate(SEEDS)
    }
    first_rank = full_seed_ranks[SEEDS[0]]
    for pkg, values in sorted(by_app_seed.items()):
        ranks = [full_seed_ranks[seed][pkg] for seed in SEEDS]
        app_rows.append(
            {
                **_app_meta(pkg, (freeze.get("apps") or {}).get(pkg, {})),
                "package_name": pkg,
                "seed_count": len(values),
                "delta_min": min(values),
                "delta_max": max(values),
                "delta_mean": _mean(values),
                "delta_sd": _sd(values),
                "baseline_rdi_min": min(by_app_baseline[pkg]),
                "baseline_rdi_max": max(by_app_baseline[pkg]),
                "interactive_rdi_min": min(by_app_interactive[pkg]),
                "interactive_rdi_max": max(by_app_interactive[pkg]),
                "rank_min": min(ranks),
                "rank_max": max(ranks),
                "rank_sd": _sd([float(r) for r in ranks]),
                "rank_at_first_seed": first_rank[pkg],
            }
        )
    return app_rows, seed_rows


def _app_phase_values_for_features(
    freeze: Mapping[str, Any],
    run_windows: Mapping[str, RunWindows],
    *,
    features: Sequence[str],
    seed: int,
) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for package_name, app in sorted((freeze.get("apps") or {}).items()):
        baseline_ids = [str(x) for x in app.get("baseline_run_ids") or []]
        interactive_ids = [str(x) for x in app.get("interactive_run_ids") or []]
        X_train = _matrix_for_runs(run_windows, baseline_ids, features=features)
        X_baseline = X_train
        X_interactive = _matrix_for_runs(run_windows, interactive_ids, features=features)
        baseline_rdi, interactive_rdi = _fit_score_rdis(X_train, [X_baseline, X_interactive], seed=seed)
        out[str(package_name)] = {
            "baseline_rdi": baseline_rdi,
            "interactive_rdi": interactive_rdi,
            "delta": interactive_rdi - baseline_rdi,
        }
    return out


def _temporal_order_control(
    freeze: Mapping[str, Any], run_windows: Mapping[str, RunWindows]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    variants = {
        "original_order": lambda rows: list(rows),
        "shuffled_order": _shuffle_rows,
        "reversed_order": lambda rows: list(reversed(rows)),
        "timestamps_removed": _strip_timestamps,
    }
    values_by_variant: dict[str, dict[str, dict[str, float]]] = {}
    feature_hashes: dict[str, str] = {}
    for name, transform in variants.items():
        variant_windows = {
            run_id: RunWindows(
                run_id=run.run_id,
                package_name=run.package_name,
                phase=run.phase,
                rows=transform(run.rows),
            )
            for run_id, run in run_windows.items()
        }
        values_by_variant[name] = _app_phase_values_for_features(
            freeze,
            variant_windows,
            features=BASIC_FEATURE_NAMES,
            seed=SEEDS[0],
        )
        feature_hashes[name] = _feature_multiset_hash(variant_windows)

    original = values_by_variant["original_order"]
    rows: list[dict[str, Any]] = []
    for variant, app_values in values_by_variant.items():
        max_abs_delta_diff = 0.0
        max_abs_baseline_diff = 0.0
        max_abs_interactive_diff = 0.0
        for package_name in sorted(original):
            base = original[package_name]
            vals = app_values[package_name]
            max_abs_delta_diff = max(max_abs_delta_diff, abs(float(vals["delta"]) - float(base["delta"])))
            max_abs_baseline_diff = max(
                max_abs_baseline_diff,
                abs(float(vals["baseline_rdi"]) - float(base["baseline_rdi"])),
            )
            max_abs_interactive_diff = max(
                max_abs_interactive_diff,
                abs(float(vals["interactive_rdi"]) - float(base["interactive_rdi"])),
            )
        feature_multiset_matches = feature_hashes[variant] == feature_hashes["original_order"]
        scores_match = (
            max_abs_delta_diff <= 1e-12
            and max_abs_baseline_diff <= 1e-12
            and max_abs_interactive_diff <= 1e-12
        )
        rows.append(
            {
                "variant": variant,
                "feature_multiset_hash": feature_hashes[variant],
                "feature_multiset_matches_original": str(feature_multiset_matches).lower(),
                "max_abs_baseline_rdi_diff_vs_original": max_abs_baseline_diff,
                "max_abs_interactive_rdi_diff_vs_original": max_abs_interactive_diff,
                "max_abs_delta_diff_vs_original": max_abs_delta_diff,
                "scores_match_original": str(scores_match).lower(),
                "interpretation": (
                    "window order is not a model input; features are time-windowed vectors, "
                    "not sequence states"
                ),
            }
        )
    summary = {
        "schema_version": "paper2_temporal_order_control_v2",
        "status": "OK",
        "method_statement": {
            "isolation_forest_sequence_model": False,
            "window_order_model_input": False,
            "timestamps_model_input": False,
            "description": (
                "The model analyzes time-windowed feature vectors. It does not model temporal "
                "dependencies or sequence transitions."
            ),
        },
        "variant_results": rows,
        "all_feature_multisets_match_original": all(row["feature_multiset_matches_original"] == "true" for row in rows),
        "all_scores_match_original": all(row["scores_match_original"] == "true" for row in rows),
    }
    return rows, summary


def _shuffle_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out = [dict(row) for row in rows]
    random.Random(20260713).shuffle(out)
    return out


def _strip_timestamps(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        clean = dict(row)
        for key in ("window_start_s", "window_end_s", "start_s", "end_s", "timestamp", "timestamp_s"):
            clean.pop(key, None)
        out.append(clean)
    return out


def _feature_multiset_hash(run_windows: Mapping[str, RunWindows]) -> str:
    rows: list[list[float]] = []
    for run in run_windows.values():
        matrix = _matrix_from_rows(run.rows, features=BASIC_FEATURE_NAMES)
        rows.extend([list(map(float, row)) for row in matrix.tolist()])
    payload = sorted([[round(value, 12) for value in row] for row in rows])
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _fit_score_rdis(X_train: np.ndarray, matrices: Sequence[np.ndarray], *, seed: int) -> list[float]:
    spec = next(item for item in fixed_model_specs(seed) if item.name == config.MODEL_IFOREST)
    model = fit_model(spec, X_train)
    scores_train = anomaly_scores(spec.name, model, X_train)
    threshold = float(np.percentile(scores_train, config.THRESHOLD_PERCENTILE, method=config.NP_PERCENTILE_METHOD))
    out: list[float] = []
    for matrix in matrices:
        scores = anomaly_scores(spec.name, model, matrix)
        out.append(float(np.mean(scores >= threshold)) if scores.size else 0.0)
    return out


def _matrix_for_runs(
    run_windows: Mapping[str, RunWindows],
    run_ids: Iterable[str],
    *,
    features: Sequence[str],
) -> np.ndarray:
    rows: list[dict[str, Any]] = []
    for run_id in run_ids:
        rows.extend(run_windows[str(run_id)].rows)
    return _matrix_from_rows(rows, features=features)


def _matrix_from_rows(rows: Sequence[Mapping[str, Any]], *, features: Sequence[str]) -> np.ndarray:
    matrix, names = rows_to_basic_matrix(
        list(rows),
        window_spec=WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S),
        feature_log1p=bool(config.FEATURE_LOG1P),
    )
    indexes = [names.index(name) for name in features]
    return matrix[:, indexes]


def _paired_summary(values: Iterable[float]) -> dict[str, Any]:
    vals = [float(v) for v in values if math.isfinite(float(v))]
    nonzero = [v for v in vals if v != 0.0]
    wilcoxon = stats.wilcoxon(nonzero, alternative="two-sided", zero_method="wilcox", method="exact")
    sd = _sd(vals)
    dz = (_mean(vals) / sd) if sd else float("inf")
    return {
        "n_apps": len(vals),
        "positive_differences": sum(1 for v in vals if v > 0),
        "negative_differences": sum(1 for v in vals if v < 0),
        "zero_differences": sum(1 for v in vals if v == 0),
        "median_delta": median(vals),
        "mean_delta": _mean(vals),
        "sd_delta": sd,
        "cohens_dz": dz,
        "rank_biserial": _rank_biserial(vals),
        "hodges_lehmann_shift": _hodges_lehmann(vals),
        "wilcoxon_w": float(wilcoxon.statistic),
        "wilcoxon_p_two_sided_exact": float(wilcoxon.pvalue),
    }


def _rank_biserial(values: Sequence[float]) -> float:
    nonzero = [float(v) for v in values if float(v) != 0.0]
    if not nonzero:
        return 0.0
    ranks = stats.rankdata([abs(v) for v in nonzero])
    pos = sum(rank for rank, value in zip(ranks, nonzero, strict=True) if value > 0)
    neg = sum(rank for rank, value in zip(ranks, nonzero, strict=True) if value < 0)
    denom = sum(ranks)
    return float((pos - neg) / denom) if denom else 0.0


def _hodges_lehmann(values: Sequence[float]) -> float:
    vals = [float(v) for v in values]
    walsh = [(a + b) / 2.0 for i, a in enumerate(vals) for b in vals[i:]]
    return float(median(walsh)) if walsh else 0.0


def _summary_table(name: str, deltas: Mapping[str, float]) -> list[dict[str, Any]]:
    return [{"analysis": name, **_paired_summary(deltas.values())}]


def _seed_cohort_summary(seed_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    medians = [float(row["median_delta"]) for row in seed_rows]
    effects = [float(row["cohens_dz"]) for row in seed_rows]
    return [
        {
            "seed_count": len(seed_rows),
            "median_delta_min": min(medians),
            "median_delta_max": max(medians),
            "cohens_dz_min": min(effects),
            "cohens_dz_max": max(effects),
            "positive_differences_min": min(int(row["positive_differences"]) for row in seed_rows),
            "positive_differences_max": max(int(row["positive_differences"]) for row in seed_rows),
            "negative_differences_max": max(int(row["negative_differences"]) for row in seed_rows),
            "zero_differences_max": max(int(row["zero_differences"]) for row in seed_rows),
            "wilcoxon_p_min": min(float(row["wilcoxon_p_two_sided_exact"]) for row in seed_rows),
            "wilcoxon_p_max": max(float(row["wilcoxon_p_two_sided_exact"]) for row in seed_rows),
        }
    ]


def _bytes_control_class(diff: float) -> str:
    if diff >= 0.10:
        return "IF_MATERIALLY_HIGHER"
    if diff <= -0.10:
        return "BYTES_CONTROL_MATERIALLY_HIGHER"
    return "EFFECTIVELY_EQUIVALENT"


def _app_meta(package_name: str, app: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "display_name": str(app.get("display_name") or _display_name(package_name)),
        "selected_version_code": str(app.get("selected_version_code") or ""),
        "selected_base_apk_sha256": str(app.get("selected_base_apk_sha256") or ""),
    }


def _display_name(package_name: str) -> str:
    return app_display_name(package_name, package_name)


def _rank_map(values: Mapping[str, float]) -> dict[str, int]:
    return {pkg: i + 1 for i, (pkg, _value) in enumerate(sorted(values.items(), key=lambda item: (-item[1], item[0])))}


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({key for row in rows for key in row.keys()})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _write_manifest(path: Path, files: Sequence[Path], *, base_dir: Path) -> Path:
    rows = [
        {
            "path": str(file.relative_to(base_dir)),
            "sha256": _sha256(file),
            "bytes": file.stat().st_size,
        }
        for file in files
    ]
    path.write_text(json.dumps({"files": rows}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_latex_summary(
    path: Path,
    heldout_summary_rows: Sequence[Mapping[str, Any]],
    ablation_rows: Sequence[Mapping[str, Any]],
    bytes_summary_rows: Sequence[Mapping[str, Any]],
    seed_cohort_rows: Sequence[Mapping[str, Any]],
    temporal_rows: Sequence[Mapping[str, Any]],
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    row_end = _tex_row_end()
    lines = [
        "% Auto-generated by generate_paper2_minimum_validation.py",
        "% Paper 2 v2 minimum validation summary tables",
        "",
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Held-out baseline validation summary. Inference is app-level, not fold-level.}",
        "\\begin{tabular}{lrrrrrr}",
        "\\hline",
        "Analysis & Apps & Pos & Neg & Zero & Median $\\Delta$ & $p$ " + row_end,
        "\\hline",
    ]
    for row in heldout_summary_rows:
        lines.append(
            _latex_row(
                [
                    "Held-out baseline",
                    row["n_apps"],
                    row["positive_differences"],
                    row["negative_differences"],
                    row["zero_differences"],
                    _fmt(row["median_delta"]),
                    _fmt(row["wilcoxon_p_two_sided_exact"]),
                ],
                row_end=row_end,
            )
        )
    lines.extend(["\\hline", "\\end{tabular}", "\\end{table}", ""])

    lines.extend(
        [
            "\\begin{table}[t]",
            "\\centering",
            "\\caption{Feature-ablation sensitivity for baseline-relative network deviation.}",
            "\\begin{tabular}{lrrrr}",
            "\\hline",
            "Feature profile & Apps & Median $\\Delta$ & $p$ & $\\rho$ vs. full " + row_end,
            "\\hline",
        ]
    )
    for row in ablation_rows:
        lines.append(
            _latex_row(
                [
                    _tex(row["feature_profile"]),
                    row["n_apps"],
                    _fmt(row["median_delta"]),
                    _fmt(row["wilcoxon_p_two_sided_exact"]),
                    _fmt(row["spearman_vs_full_model"]),
                ],
                row_end=row_end,
            )
        )
    lines.extend(["\\hline", "\\end{tabular}", "\\end{table}", ""])

    if bytes_summary_rows:
        row = bytes_summary_rows[0]
        lines.extend(
            [
                "\\begin{table}[t]",
                "\\centering",
                "\\caption{Bytes/sec P95 control summary.}",
                "\\begin{tabular}{lrrrr}",
                "\\hline",
                "Control & Apps & Median $\\Delta$ & $p$ & $\\rho$ vs. IF " + row_end,
                "\\hline",
                _latex_row(
                    [
                        "Bytes/sec P95",
                        row["n_apps"],
                        _fmt(row["median_delta"]),
                        _fmt(row["wilcoxon_p_two_sided_exact"]),
                        _fmt(row["spearman_vs_iforest_delta"]),
                    ],
                    row_end=row_end,
                ),
                "\\hline",
                "\\end{tabular}",
                "\\end{table}",
                "",
            ]
        )

    if seed_cohort_rows:
        row = seed_cohort_rows[0]
        lines.extend(
            [
                "\\begin{table}[t]",
                "\\centering",
                "\\caption{Twenty-seed stability summary.}",
                "\\begin{tabular}{lrrrr}",
                "\\hline",
                "Seeds & Median $\\Delta$ min & Median $\\Delta$ max & $d_z$ min & $d_z$ max " + row_end,
                "\\hline",
                _latex_row(
                    [
                        row["seed_count"],
                        _fmt(row["median_delta_min"]),
                        _fmt(row["median_delta_max"]),
                        _fmt(row["cohens_dz_min"]),
                        _fmt(row["cohens_dz_max"]),
                    ],
                    row_end=row_end,
                ),
                "\\hline",
                "\\end{tabular}",
                "\\end{table}",
                "",
            ]
        )

    lines.extend(
        [
            "\\begin{table}[t]",
            "\\centering",
            "\\caption{Temporal-order control.}",
            "\\begin{tabular}{lrr}",
            "\\hline",
            "Variant & Feature multiset same & Scores same " + row_end,
            "\\hline",
        ]
    )
    for row in temporal_rows:
        lines.append(
            _latex_row(
                [
                    _tex(row["variant"]),
                    row["feature_multiset_matches_original"],
                    row["scores_match_original"],
                ],
                row_end=row_end,
            )
        )
    lines.extend(["\\hline", "\\end{tabular}", "\\end{table}", ""])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _fmt(value: Any) -> str:
    try:
        return f"{float(value):.4g}"
    except Exception:
        return str(value)


def _latex_row(cells: Sequence[Any], *, row_end: str) -> str:
    return " & ".join(str(cell) for cell in cells) + " " + row_end


def _tex(value: Any) -> str:
    return str(value).replace("_", "\\_")


def _tex_row_end() -> str:
    return "\\\\"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _source_revision() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
    except Exception:
        return "unknown"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _mean(values: Sequence[float]) -> float:
    return float(mean(values)) if values else 0.0


def _sd(values: Sequence[float]) -> float:
    return float(pstdev(values)) if len(values) > 1 else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
