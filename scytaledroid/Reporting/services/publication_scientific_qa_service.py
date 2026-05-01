"""Runtime service for frozen-archive scientific QA generation."""

from __future__ import annotations

import csv
import hashlib
import json
import statistics
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import scipy.stats

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.ml import deliverable_bundle_paths as bundle_paths
from scytaledroid.Utils.IO.csv_with_provenance import read_csv_with_provenance


def _freeze_path() -> Path:
    return Path(app_config.DATA_DIR) / "archive" / "dataset_freeze.json"


def _evidence_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _publication_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "publication"


def _internal_baseline_root() -> Path:
    return bundle_paths.existing_phase_e_bundle_root()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_csv_skip_comments(path: Path) -> list[dict[str, str]]:
    return read_csv_with_provenance(path).rows


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_anomaly_scores(path: Path) -> list[dict[str, str]]:
    reader = csv.DictReader(path.read_text(encoding="utf-8", errors="strict").splitlines())
    return [dict(row) for row in reader]


@dataclass(frozen=True)
class RunMetrics:
    run_id: str
    package_name: str
    run_profile: str
    window_count_manifest: int
    threshold_percentile: float
    threshold_value: float
    n_windows_scores: int
    anomalous_ge_count: int
    exceed_ge: float
    exceed_gt: float


def _compute_run_metrics(*, run_dir: Path) -> RunMetrics:
    rid = run_dir.name
    manifest = _read_json(run_dir / "run_manifest.json")
    target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    pkg = str(target.get("package_name") or "").strip().lower()
    dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
    operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    run_profile = str(operator.get("run_profile") or dataset.get("run_profile") or "").strip()
    try:
        window_count = int(dataset.get("window_count")) if dataset.get("window_count") not in (None, "") else 0
    except Exception:
        window_count = 0

    ml_dir = run_dir / "analysis" / "ml" / "v1"
    thresholds = _read_json(ml_dir / "baseline_threshold.json")
    if_model = ((thresholds.get("models") or {}).get("isolation_forest") or {}) if isinstance(thresholds.get("models"), dict) else {}
    percentile = float(if_model.get("threshold_percentile") or thresholds.get("threshold_percentile") or 95.0)
    tau = float(if_model.get("threshold_value"))

    scores_rows = _read_anomaly_scores(ml_dir / "anomaly_scores_iforest.csv")
    scores = [float(row["score"]) for row in scores_rows]
    n = len(scores)
    if n <= 0:
        anom_ge = 0
        exceed_ge = 0.0
        exceed_gt = 0.0
    else:
        anom_ge = int(sum(1 for score in scores if score >= tau))
        exceed_ge = float(anom_ge / n)
        exceed_gt = float(sum(1 for score in scores if score > tau) / n)

    return RunMetrics(
        run_id=rid,
        package_name=pkg,
        run_profile=run_profile,
        window_count_manifest=window_count,
        threshold_percentile=percentile,
        threshold_value=tau,
        n_windows_scores=n,
        anomalous_ge_count=anom_ge,
        exceed_ge=exceed_ge,
        exceed_gt=exceed_gt,
    )


def generate_scientific_qa() -> dict[str, Path]:
    """Generate frozen-cohort scientific QA artifacts under ``output/publication/qa``."""

    freeze_path = _freeze_path()
    evidence_root = _evidence_root()
    pub_root = _publication_root()
    qa_dir = pub_root / "qa"
    baseline_root = _internal_baseline_root()
    table_1 = baseline_root / "tables" / "table_1_rdi_prevalence.csv"
    table_7 = baseline_root / "tables" / "table_7_exposure_deviation_summary.csv"
    app_order = pub_root / "manifests" / "app_ordering.json"
    display_map = pub_root / "manifests" / "display_name_map.json"

    for path in (freeze_path, table_1, table_7, app_order, display_map):
        if not path.exists():
            raise RuntimeError(f"Missing required input: {path}")

    freeze = _read_json(freeze_path)
    freeze_sha = _sha256_file(freeze_path)
    freeze_hash = str(freeze.get("freeze_dataset_hash") or "")
    order = json.loads(app_order.read_text(encoding="utf-8"))
    display = json.loads(display_map.read_text(encoding="utf-8"))

    t1 = _read_csv_skip_comments(table_1)
    t7 = _read_csv_skip_comments(table_7)
    t1_by_app = {str(row.get("app") or "").strip(): row for row in t1 if str(row.get("app") or "").strip()}
    t7_by_pkg = {str(row.get("package_name") or "").strip(): row for row in t7 if str(row.get("package_name") or "").strip()}

    apps = freeze.get("apps") or {}
    if not isinstance(apps, dict) or len(apps) != 12:
        raise RuntimeError(f"Unexpected freeze apps size: {len(apps) if isinstance(apps, dict) else 'non-dict'}")

    included = [str(x) for x in (freeze.get("included_run_ids") or [])]
    if len(included) != 36:
        raise RuntimeError(f"Unexpected included_run_ids count: {len(included)} (expected 36)")
    if len(set(included)) != len(included):
        raise RuntimeError("Duplicate run IDs detected in included_run_ids")

    run_metrics: dict[str, RunMetrics] = {}
    for rid in included:
        run_dir = evidence_root / rid
        if not run_dir.exists():
            raise RuntimeError(f"Missing evidence dir for run_id: {rid}")
        run_metrics[rid] = _compute_run_metrics(run_dir=run_dir)

    per_app: list[dict[str, object]] = []
    warnings: list[str] = []
    all_windows: list[int] = []
    idle_rdi_from_scores: list[float] = []
    interactive_rdi_from_scores: list[float] = []
    deltas: list[float] = []
    spearman_pairs: list[tuple[float, float]] = []

    for pkg in order:
        pkg = str(pkg).strip().lower()
        if pkg not in apps:
            raise RuntimeError(f"Freeze missing app entry for package: {pkg}")
        entry = apps[pkg] or {}
        base_ids = [str(x) for x in (entry.get("baseline_run_ids") or [])]
        int_ids = [str(x) for x in (entry.get("interactive_run_ids") or [])]
        if len(base_ids) != 1 or len(int_ids) != 2:
            raise RuntimeError(f"Bad freeze pairing for {pkg}: baseline={len(base_ids)} interactive={len(int_ids)}")

        for rid in base_ids + int_ids:
            if rid not in run_metrics:
                raise RuntimeError(f"Run id {rid} for {pkg} not found in included_run_ids")

        base = run_metrics[base_ids[0]]
        ints = [run_metrics[rid] for rid in int_ids]
        thresholds = [base.threshold_value] + [m.threshold_value for m in ints]
        if max(thresholds) - min(thresholds) > 1e-12:
            warnings.append(f"Threshold drift across runs for {pkg} (expected invariant tau): {thresholds}")

        if not (0.02 <= base.exceed_ge <= 0.10):
            warnings.append(f"Baseline exceedance out of expected range for {pkg}: {base.exceed_ge:.3f}")

        idle_rdi = float(base.exceed_ge)
        interactive_vals = [m.exceed_ge for m in ints]
        interactive_mean_unweighted = float(statistics.mean(interactive_vals))
        total_anom = int(sum(m.anomalous_ge_count for m in ints))
        total_n = int(sum(m.n_windows_scores for m in ints))
        interactive_mean_weighted = float(total_anom / total_n) if total_n > 0 else 0.0
        delta = float(interactive_mean_weighted - idle_rdi)
        idle_rdi_from_scores.append(idle_rdi)
        interactive_rdi_from_scores.append(interactive_mean_weighted)
        deltas.append(delta)

        all_windows.extend([base.n_windows_scores] + [m.n_windows_scores for m in ints])
        if abs(base.n_windows_scores - base.window_count_manifest) > 2:
            warnings.append(f"baseline window_count mismatch (>2) for {pkg}: manifest={base.window_count_manifest} ml={base.n_windows_scores}")
        for m in ints:
            if abs(m.n_windows_scores - m.window_count_manifest) > 2:
                warnings.append(f"scripted window_count mismatch (>2) for {pkg}: manifest={m.window_count_manifest} ml={m.n_windows_scores}")

        app_name = str(display.get(pkg, pkg))
        t1_row = t1_by_app.get(app_name)
        if not t1_row:
            warnings.append(f"Table 1 missing row for app label: {app_name}")
            t1_if_idle = None
            t1_if_inter = None
        else:
            t1_if_idle = float(t1_row["if_idle"])
            t1_if_inter = float(t1_row["if_interactive"])
            if abs(t1_if_idle - idle_rdi) > 0.01:
                warnings.append(f"Table 1 idle mismatch for {app_name}: table={t1_if_idle:.6f} recomputed={idle_rdi:.6f}")
            if abs(t1_if_inter - interactive_mean_weighted) > 0.01:
                warnings.append(
                    f"Table 1 interactive mismatch for {app_name}: table={t1_if_inter:.6f} recomputed_weighted={interactive_mean_weighted:.6f} unweighted={interactive_mean_unweighted:.6f}"
                )

        t7_row = t7_by_pkg.get(pkg)
        if not t7_row:
            warnings.append(f"Table 7 missing row for package: {pkg}")
            static_score = float("nan")
        else:
            static_score = float(t7_row["static_exposure_score"])
        spearman_pairs.append((static_score, interactive_mean_weighted))

        per_app.append(
            {
                "app": app_name,
                "package_name": pkg,
                "run_ids": {"baseline": base_ids, "interactive": int_ids, "scripted": int_ids},
                "windows": {
                    "baseline": base.n_windows_scores,
                    "interactive_1": ints[0].n_windows_scores,
                    "interactive_2": ints[1].n_windows_scores,
                    "scripted_1": ints[0].n_windows_scores,
                    "scripted_2": ints[1].n_windows_scores,
                },
                "threshold": {"percentile": base.threshold_percentile, "tau": base.threshold_value},
                "rdi_recomputed": {
                    "idle": idle_rdi,
                    "interactive_runs": interactive_vals,
                    "interactive_mean_unweighted": interactive_mean_unweighted,
                    "interactive_mean_weighted": interactive_mean_weighted,
                    "scripted_runs": interactive_vals,
                    "scripted_mean_unweighted": interactive_mean_unweighted,
                    "scripted_mean_weighted": interactive_mean_weighted,
                    "delta": delta,
                },
                "table_1_if": {"idle": t1_if_idle, "interactive_mean": t1_if_inter},
            }
        )

    windows_mean = float(statistics.mean(all_windows))
    windows_sd = float(statistics.pstdev(all_windows)) if len(all_windows) > 1 else 0.0
    if windows_sd > 0:
        for window_count in all_windows:
            z = abs((window_count - windows_mean) / windows_sd)
            if z > 3.5:
                warnings.append(f"Extreme window_count outlier detected (z>{z:.2f}): {window_count}")

    xs = [pair[0] for pair in spearman_pairs]
    ys = [pair[1] for pair in spearman_pairs]
    sp = scipy.stats.spearmanr(xs, ys)
    w = scipy.stats.wilcoxon(
        idle_rdi_from_scores,
        interactive_rdi_from_scores,
        alternative="two-sided",
        zero_method="wilcox",
        method="auto",
    )
    unique_static = len(set(xs))
    static_sd = float(statistics.pstdev(xs)) if len(xs) > 1 else 0.0
    if unique_static <= 3:
        warnings.append(f"Low static-score variability detected: unique_static={unique_static}")

    qa_dir.mkdir(parents=True, exist_ok=True)
    structure_path = qa_dir / "qa_cohort_structure_report.json"
    structure_payload = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "freeze_anchor": str(freeze_path),
        "freeze_sha256": freeze_sha,
        "freeze_dataset_hash": freeze_hash,
        "n_apps_expected": 12,
        "n_runs_expected": 36,
        "n_apps": len(per_app),
        "n_runs": len(included),
        "pairing": {"idle_per_app": 1, "interactive_per_app": 2},
        "windows_per_run": {"mean": windows_mean, "sd_pop": windows_sd, "min": int(min(all_windows)), "max": int(max(all_windows))},
        "static_exposure_score": {"min": float(min(xs)), "max": float(max(xs)), "sd_pop": static_sd, "unique": unique_static},
        "warnings": warnings,
        "per_app": per_app,
    }
    structure_path.write_text(json.dumps(structure_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    dist_path = qa_dir / "qa_distribution_summary.csv"
    with dist_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "app",
            "package_name",
            "idle_rdi",
            "interactive_rdi_mean",
            "delta",
            "idle_windows",
            "interactive_windows_total",
            "interactive_rdi_run_1",
            "interactive_rdi_run_2",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in per_app:
            windows = row["windows"]
            rdi = row["rdi_recomputed"]
            vals = list(rdi["scripted_runs"])
            writer.writerow(
                {
                    "app": row["app"],
                    "package_name": row["package_name"],
                    "idle_rdi": f"{float(rdi['idle']):.6f}",
                    "interactive_rdi_mean": f"{float(rdi['scripted_mean_weighted']):.6f}",
                    "delta": f"{float(rdi['delta']):.6f}",
                    "idle_windows": int(windows["baseline"]),
                    "interactive_windows_total": int(windows["scripted_1"]) + int(windows["scripted_2"]),
                    "interactive_rdi_run_1": f"{float(vals[0]) if len(vals) >= 1 else float('nan'):.6f}",
                    "interactive_rdi_run_2": f"{float(vals[1]) if len(vals) >= 2 else float('nan'):.6f}",
                }
            )

    thr_path = qa_dir / "qa_threshold_validation.csv"
    with thr_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "app",
            "package_name",
            "baseline_windows",
            "tau_percentile",
            "tau_value",
            "baseline_exceed_ge",
            "baseline_exceed_gt",
            "baseline_expected_exceedance",
            "baseline_exceed_abs_error",
            "baseline_exceed_ok",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in per_app:
            rid = row["run_ids"]["baseline"][0]
            metric = run_metrics[rid]
            expected = 0.05
            abs_err = abs(float(metric.exceed_ge) - expected)
            writer.writerow(
                {
                    "app": row["app"],
                    "package_name": row["package_name"],
                    "baseline_windows": metric.n_windows_scores,
                    "tau_percentile": f"{metric.threshold_percentile:.1f}",
                    "tau_value": f"{metric.threshold_value:.12g}",
                    "baseline_exceed_ge": f"{metric.exceed_ge:.6f}",
                    "baseline_exceed_gt": f"{metric.exceed_gt:.6f}",
                    "baseline_expected_exceedance": f"{expected:.6f}",
                    "baseline_exceed_abs_error": f"{abs_err:.6f}",
                    "baseline_exceed_ok": bool(abs_err <= 0.03),
                }
            )

    stats_path = qa_dir / "qa_stats_validation.json"
    stats_payload = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "freeze_anchor": str(freeze_path),
        "freeze_sha256": freeze_sha,
        "freeze_dataset_hash": freeze_hash,
        "unit_of_analysis": "application (n=12), paired idle vs interactive means",
        "baseline_integrity": {
            "threshold_source": "tau = P95(baseline anomaly scores) computed from baseline run windows only",
            "training_scope": "per-app",
            "training_mode": "baseline_only",
            "leakage_between_idle_and_interactive": False,
        },
        "wilcoxon": {
            "n": len(deltas),
            "idle_rdi": idle_rdi_from_scores,
            "interactive_rdi_mean": interactive_rdi_from_scores,
            "deltas": deltas,
            "W": float(w.statistic) if w.statistic is not None else None,
            "p": float(w.pvalue) if w.pvalue is not None else None,
        },
        "spearman": {
            "n": len(spearman_pairs),
            "pairs": [{"static_exposure_score": float(a), "interactive_rdi_mean": float(b)} for a, b in spearman_pairs],
            "rho": float(sp.statistic),
            "p": float(sp.pvalue),
            "unique_static_scores": unique_static,
            "static_score_min": float(min(xs)) if xs else None,
            "static_score_max": float(max(xs)) if xs else None,
            "static_score_mean": float(sum(xs) / float(len(xs))) if xs else None,
            "static_score_sd_sample": float(statistics.stdev(xs)) if xs and len(xs) > 1 else None,
        },
    }
    stats_path.write_text(json.dumps(stats_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        "qa_structure_report": structure_path,
        "qa_distribution_summary": dist_path,
        "qa_threshold_validation": thr_path,
        "qa_stats_validation": stats_path,
    }


def main() -> int:
    outputs = generate_scientific_qa()
    print(outputs["qa_structure_report"])
    print(outputs["qa_distribution_summary"])
    print(outputs["qa_threshold_validation"])
    print(outputs["qa_stats_validation"])
    return 0
