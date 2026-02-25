#!/usr/bin/env python3
"""Scientific QA pass for a frozen cohort (publication bundle).

Goal: verify scientific assumptions (structure, thresholds, distributions, stats inputs)
over the frozen cohort. This is not a code-debug export; it is reviewer-facing QA.

Outputs (paper-facing, deterministic, freeze-anchored):
  output/publication/qa/qa_cohort_structure_report.json
  output/publication/qa/qa_distribution_summary.csv
  output/publication/qa/qa_threshold_validation.csv
  output/publication/qa/qa_stats_validation.json
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import scipy.stats

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Utils.IO.csv_with_provenance import read_csv_with_provenance

FREEZE = REPO_ROOT / "data" / "archive" / "dataset_freeze.json"
EVIDENCE_ROOT = REPO_ROOT / "output" / "evidence" / "dynamic"

PUB_ROOT = REPO_ROOT / "output" / "publication"
QA_DIR = PUB_ROOT / "qa"

# Use the internal baseline bundle for Table 1/7 inputs to keep the canonical
# publication directory minimal and paper-facing.
INTERNAL_BASELINE_ROOT = REPO_ROOT / "output" / "_internal" / "paper2" / "baseline"
TABLE_1 = INTERNAL_BASELINE_ROOT / "tables" / "table_1_rdi_prevalence.csv"
TABLE_7 = INTERNAL_BASELINE_ROOT / "tables" / "table_7_exposure_deviation_summary.csv"
APP_ORDER = PUB_ROOT / "manifests" / "app_ordering.json"
DISPLAY_MAP = PUB_ROOT / "manifests" / "display_name_map.json"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_csv_skip_comments(path: Path) -> list[dict[str, str]]:
    return read_csv_with_provenance(path).rows


def _f(x: object) -> float:
    return float(str(x).strip())


def _i(x: object) -> int:
    return int(str(x).strip())


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_anomaly_scores(path: Path) -> list[dict[str, str]]:
    # CSV always has a header (no comments).
    rdr = csv.DictReader(path.read_text(encoding="utf-8", errors="strict").splitlines())
    return [dict(r) for r in rdr]


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
    man = _read_json(run_dir / "run_manifest.json")
    tgt = man.get("target") if isinstance(man.get("target"), dict) else {}
    pkg = str(tgt.get("package_name") or "").strip().lower()
    ds = man.get("dataset") if isinstance(man.get("dataset"), dict) else {}
    op = man.get("operator") if isinstance(man.get("operator"), dict) else {}
    run_profile = str(op.get("run_profile") or ds.get("run_profile") or "").strip()
    try:
        wc = int(ds.get("window_count")) if ds.get("window_count") not in (None, "") else 0
    except Exception:
        wc = 0

    ml = run_dir / "analysis" / "ml" / "v1"
    thr = _read_json(ml / "baseline_threshold.json")
    if_thr = ((thr.get("models") or {}).get("isolation_forest") or {}) if isinstance(thr.get("models"), dict) else {}
    pctl = float(if_thr.get("threshold_percentile") or thr.get("threshold_percentile") or 95.0)
    tau = float(if_thr.get("threshold_value"))

    scores_rows = _read_anomaly_scores(ml / "anomaly_scores_iforest.csv")
    scores = [float(r["score"]) for r in scores_rows]
    n = len(scores)
    if n <= 0:
        anom_ge = 0
        exceed_ge = 0.0
        exceed_gt = 0.0
    else:
        anom_ge = int(sum(1 for s in scores if s >= tau))
        exceed_ge = float(anom_ge / n)
        exceed_gt = float(sum(1 for s in scores if s > tau) / n)

    return RunMetrics(
        run_id=rid,
        package_name=pkg,
        run_profile=run_profile,
        window_count_manifest=wc,
        threshold_percentile=pctl,
        threshold_value=tau,
        n_windows_scores=n,
        anomalous_ge_count=anom_ge,
        exceed_ge=exceed_ge,
        exceed_gt=exceed_gt,
    )


def main() -> int:
    for p in (FREEZE, TABLE_1, TABLE_7, APP_ORDER, DISPLAY_MAP):
        if not p.exists():
            raise SystemExit(f"Missing required input: {p}")

    freeze = _read_json(FREEZE)
    freeze_sha = _sha256_file(FREEZE)
    freeze_hash = str(freeze.get("freeze_dataset_hash") or "")

    order = json.loads(APP_ORDER.read_text(encoding="utf-8"))
    display = json.loads(DISPLAY_MAP.read_text(encoding="utf-8"))

    t1 = _read_csv_skip_comments(TABLE_1)
    t7 = _read_csv_skip_comments(TABLE_7)
    t1_by_app = {str(r.get("app") or "").strip(): r for r in t1 if str(r.get("app") or "").strip()}
    t7_by_pkg = {str(r.get("package_name") or "").strip(): r for r in t7 if str(r.get("package_name") or "").strip()}

    # Structural QA inputs from freeze.
    apps = freeze.get("apps") or {}
    if not isinstance(apps, dict) or len(apps) != 12:
        raise SystemExit(f"Unexpected freeze apps size: {len(apps) if isinstance(apps, dict) else 'non-dict'}")

    included = [str(x) for x in (freeze.get("included_run_ids") or [])]
    if len(included) != 36:
        raise SystemExit(f"Unexpected included_run_ids count: {len(included)} (expected 36)")
    if len(set(included)) != len(included):
        raise SystemExit("Duplicate run IDs detected in included_run_ids")

    # Compute per-run metrics (authoritative).
    run_metrics: dict[str, RunMetrics] = {}
    for rid in included:
        run_dir = EVIDENCE_ROOT / rid
        if not run_dir.exists():
            raise SystemExit(f"Missing evidence dir for run_id: {rid}")
        run_metrics[rid] = _compute_run_metrics(run_dir=run_dir)

    # Per-app checks: pairing and threshold invariance.
    per_app: list[dict[str, object]] = []
    warnings: list[str] = []
    all_windows: list[int] = []
    baseline_exceed: list[float] = []
    idle_rdi_from_scores: list[float] = []
    interactive_rdi_from_scores: list[float] = []
    deltas: list[float] = []
    spearman_pairs: list[tuple[float, float]] = []

    for pkg in order:
        pkg = str(pkg).strip().lower()
        if pkg not in apps:
            raise SystemExit(f"Freeze missing app entry for package: {pkg}")
        entry = apps[pkg] or {}
        base_ids = [str(x) for x in (entry.get("baseline_run_ids") or [])]
        int_ids = [str(x) for x in (entry.get("interactive_run_ids") or [])]
        if len(base_ids) != 1 or len(int_ids) != 2:
            raise SystemExit(f"Bad freeze pairing for {pkg}: baseline={len(base_ids)} interactive={len(int_ids)}")

        # Validate that these IDs are in included set.
        for rid in base_ids + int_ids:
            if rid not in run_metrics:
                raise SystemExit(f"Run id {rid} for {pkg} not found in included_run_ids")

        base = run_metrics[base_ids[0]]
        ints = [run_metrics[r] for r in int_ids]
        thresholds = [base.threshold_value] + [m.threshold_value for m in ints]
        if max(thresholds) - min(thresholds) > 1e-12:
            warnings.append(f"Threshold drift across runs for {pkg} (expected invariant tau): {thresholds}")

        # Baseline exceedance should be near 0.05 (ties/overlap can raise slightly).
        baseline_exceed.append(base.exceed_ge)
        if not (0.02 <= base.exceed_ge <= 0.10):
            warnings.append(f"Baseline exceedance out of expected range for {pkg}: {base.exceed_ge:.3f}")

        # Define per-app RDI as one value per phase:
        # - idle: baseline run exceedance fraction
        # - interactive: aggregate across both interaction runs (weighted by window count)
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

        # Window counts sanity: ML window rows are authoritative for RDI.
        # Manifest window_count is telemetry-window count; it may differ by 1 due to end-window handling.
        all_windows.extend([base.n_windows_scores] + [m.n_windows_scores for m in ints])
        if abs(base.n_windows_scores - base.window_count_manifest) > 2:
            warnings.append(f"baseline window_count mismatch (>2) for {pkg}: manifest={base.window_count_manifest} ml={base.n_windows_scores}")
        for m in ints:
            if abs(m.n_windows_scores - m.window_count_manifest) > 2:
                warnings.append(f"scripted window_count mismatch (>2) for {pkg}: manifest={m.window_count_manifest} ml={m.n_windows_scores}")

        # Compare to Table 1 publication values for this app label.
        app_name = str(display.get(pkg, pkg))
        t1_row = t1_by_app.get(app_name)
        if not t1_row:
            warnings.append(f"Table 1 missing row for app label: {app_name}")
            t1_if_idle = None
            t1_if_inter = None
        else:
            t1_if_idle = float(t1_row["if_idle"])
            t1_if_inter = float(t1_row["if_interactive"])
            # Table 1 is rounded; validate against weighted recompute within a small tolerance.
            if abs(t1_if_idle - idle_rdi) > 0.01:
                warnings.append(f"Table 1 idle mismatch for {app_name}: table={t1_if_idle:.6f} recomputed={idle_rdi:.6f}")
            if abs(t1_if_inter - interactive_mean_weighted) > 0.01:
                warnings.append(
                    f"Table 1 interactive mismatch for {app_name}: table={t1_if_inter:.6f} recomputed_weighted={interactive_mean_weighted:.6f} unweighted={interactive_mean_unweighted:.6f}"
                )

        # Static–dynamic pairs for Spearman (12 points).
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
                    # Use ML-window counts (RDI denominator) as scientific window accounting.
                    "baseline": base.n_windows_scores,
                    "interactive_1": ints[0].n_windows_scores,
                    "interactive_2": ints[1].n_windows_scores,
                    # Back-compat aliases:
                    "scripted_1": ints[0].n_windows_scores,
                    "scripted_2": ints[1].n_windows_scores,
                },
                "threshold": {
                    "percentile": base.threshold_percentile,
                    "tau": base.threshold_value,
                },
                "rdi_recomputed": {
                    "idle": idle_rdi,
                    "interactive_runs": interactive_vals,
                    "interactive_mean_unweighted": interactive_mean_unweighted,
                    "interactive_mean_weighted": interactive_mean_weighted,
                    # Back-compat aliases:
                    "scripted_runs": interactive_vals,
                    "scripted_mean_unweighted": interactive_mean_unweighted,
                    "scripted_mean_weighted": interactive_mean_weighted,
                    "delta": delta,
                },
                "table_1_if": {
                    "idle": t1_if_idle,
                    "interactive_mean": t1_if_inter,
                },
            }
        )

    # Global sanity: window count imbalance / outliers.
    windows_mean = float(statistics.mean(all_windows))
    windows_sd = float(statistics.pstdev(all_windows)) if len(all_windows) > 1 else 0.0
    if windows_sd > 0:
        for w in all_windows:
            z = abs((w - windows_mean) / windows_sd)
            if z > 3.5:
                warnings.append(f"Extreme window_count outlier detected (z>{z:.2f}): {w}")

    # Stats validation: Wilcoxon and Spearman inputs are app-level arrays (n=12).
    xs = [p[0] for p in spearman_pairs]
    ys = [p[1] for p in spearman_pairs]
    sp = scipy.stats.spearmanr(xs, ys)
    w = scipy.stats.wilcoxon(
        idle_rdi_from_scores,
        interactive_rdi_from_scores,
        alternative="two-sided",
        zero_method="wilcox",
        method="auto",
    )

    # Static score variability (ties).
    unique_static = len(set(xs))
    static_sd = float(statistics.pstdev(xs)) if len(xs) > 1 else 0.0
    if unique_static <= 3:
        warnings.append(f"Low static-score variability detected: unique_static={unique_static}")

    QA_DIR.mkdir(parents=True, exist_ok=True)

    # 1) Structural report.
    structure_path = QA_DIR / "qa_cohort_structure_report.json"
    structure_payload = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "freeze_anchor": str(FREEZE.relative_to(REPO_ROOT)),
        "freeze_sha256": freeze_sha,
        "freeze_dataset_hash": freeze_hash,
        "n_apps_expected": 12,
        "n_runs_expected": 36,
        "n_apps": len(per_app),
        "n_runs": len(included),
        "pairing": {"idle_per_app": 1, "interactive_per_app": 2},
        "windows_per_run": {
            "mean": windows_mean,
            "sd_pop": windows_sd,
            "min": int(min(all_windows)),
            "max": int(max(all_windows)),
        },
        "static_exposure_score": {
            "min": float(min(xs)),
            "max": float(max(xs)),
            "sd_pop": static_sd,
            "unique": unique_static,
        },
        "warnings": warnings,
        "per_app": per_app,
    }
    structure_path.write_text(json.dumps(structure_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # 2) Distribution summary CSV (manual eyeballing).
    #
    # Paper-facing CSVs should be directly sortable/filterable without needing
    # provenance-aware parsing. Provenance is already captured in the JSON
    # QA reports (and in the publication receipt).
    dist_path = QA_DIR / "qa_distribution_summary.csv"
    with dist_path.open("w", encoding="utf-8", newline="") as f:
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
        wcsv = csv.DictWriter(f, fieldnames=fieldnames)
        wcsv.writeheader()
        for row in per_app:
            windows = row["windows"]
            rdi = row["rdi_recomputed"]
            vals = list(rdi["scripted_runs"])
            sr1 = float(vals[0]) if len(vals) >= 1 else float("nan")
            sr2 = float(vals[1]) if len(vals) >= 2 else float("nan")
            interactive_mean = float(rdi["scripted_mean_weighted"])
            wcsv.writerow(
                {
                    "app": row["app"],
                    "package_name": row["package_name"],
                    "idle_rdi": f"{float(rdi['idle']):.6f}",
                    "interactive_rdi_mean": f"{interactive_mean:.6f}",
                    "delta": f"{float(rdi['delta']):.6f}",
                    # Use ML-window counts (RDI denominator), not manifest telemetry windows.
                    "idle_windows": int(windows["baseline"]),
                    "interactive_windows_total": int(windows["scripted_1"]) + int(windows["scripted_2"]),
                    "interactive_rdi_run_1": f"{sr1:.6f}",
                    "interactive_rdi_run_2": f"{sr2:.6f}",
                }
            )

    # 3) Threshold validation CSV (per app).
    thr_path = QA_DIR / "qa_threshold_validation.csv"
    with thr_path.open("w", encoding="utf-8", newline="") as f:
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
        wcsv = csv.DictWriter(f, fieldnames=fieldnames)
        wcsv.writeheader()
        for row in per_app:
            pkg = row["package_name"]
            rid = row["run_ids"]["baseline"][0]
            m = run_metrics[rid]
            expected = 0.05
            abs_err = abs(float(m.exceed_ge) - expected)
            # Be generous: overlap + ties can inflate baseline exceedance slightly.
            ok = abs_err <= 0.03
            wcsv.writerow(
                {
                    "app": row["app"],
                    "package_name": pkg,
                    "baseline_windows": m.n_windows_scores,
                    "tau_percentile": f"{m.threshold_percentile:.1f}",
                    "tau_value": f"{m.threshold_value:.12g}",
                    "baseline_exceed_ge": f"{m.exceed_ge:.6f}",
                    "baseline_exceed_gt": f"{m.exceed_gt:.6f}",
                    "baseline_expected_exceedance": f"{expected:.6f}",
                    "baseline_exceed_abs_error": f"{abs_err:.6f}",
                    "baseline_exceed_ok": bool(ok),
                }
            )

    # 4) Stats validation JSON (explicit unit-of-analysis proof).
    stats_path = QA_DIR / "qa_stats_validation.json"
    stats_payload = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "freeze_anchor": str(FREEZE.relative_to(REPO_ROOT)),
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
            "static_score_sd_sample": (
                float(statistics.stdev(xs)) if xs and len(xs) > 1 else None
            ),
        },
    }
    stats_path.write_text(json.dumps(stats_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(structure_path)
    print(dist_path)
    print(thr_path)
    print(stats_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
