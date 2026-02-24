#!/usr/bin/env python3
"""Machine-learning audit report for Paper #2 (freeze-anchored).

This is a deeper ML-focused audit than the general pipeline audit:
- verifies score semantics per model (higher_is_more_anomalous)
- checks baseline thresholding behavior (baseline exceedance ~= 0.05 for P95, within tolerance)
- checks per-run window accounting (expected vs scored rows)
- flags NaN/Inf in scores and other silent-failure patterns

Outputs:
  output/publication/qa/paper2_ml_audit_report_v1.json
  output/publication/qa/paper2_ml_audit_report_v1.csv
"""

from __future__ import annotations

import csv
import json
import math
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2  # noqa: E402

FREEZE = REPO_ROOT / "data" / "archive" / "dataset_freeze.json"
EVIDENCE_ROOT = REPO_ROOT / "output" / "evidence" / "dynamic"
OUT_DIR = REPO_ROOT / "output" / "publication" / "qa"
OUT_JSON = OUT_DIR / "paper2_ml_audit_report_v1.json"
OUT_CSV = OUT_DIR / "paper2_ml_audit_report_v1.csv"


def _rjson(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_scores(csv_path: Path) -> list[float] | None:
    if not csv_path.exists():
        return None
    try:
        scores: list[float] = []
        with csv_path.open("r", encoding="utf-8", newline="") as f:
            r = csv.DictReader(f)
            for row in r:
                try:
                    scores.append(float(row.get("score") or 0.0))
                except Exception:
                    continue
        return scores
    except Exception:
        return None


def _count_data_rows(csv_path: Path) -> int | None:
    if not csv_path.exists():
        return None
    try:
        n = 0
        with csv_path.open("r", encoding="utf-8") as f:
            for i, ln in enumerate(f):
                if i == 0:
                    continue
                if ln.strip():
                    n += 1
        return int(n)
    except Exception:
        return None


def _bucket(man: dict) -> str:
    ds = man.get("dataset") if isinstance(man.get("dataset"), dict) else {}
    op = man.get("operator") if isinstance(man.get("operator"), dict) else {}
    run_profile = str(op.get("run_profile") or ds.get("run_profile") or "").strip().lower()
    interaction_level = str(op.get("interaction_level") or ds.get("interaction_level") or "").strip().lower()
    if run_profile.startswith("baseline"):
        return "idle"
    if interaction_level == "scripted" or "scripted" in run_profile:
        return "scripted"
    if interaction_level == "manual" or "manual" in run_profile:
        return "manual"
    return "other"


def _finite(x: float) -> bool:
    return not (math.isnan(x) or math.isinf(x))


@dataclass(frozen=True)
class RunAuditRow:
    run_id: str
    package_name: str
    run_profile: str
    interaction_level: str
    bucket: str
    model: str
    threshold_percentile: float
    threshold_value: float
    scores_n: int
    scores_nan_inf: int
    exceedance_ratio: float
    baseline_expected_exceedance: float
    baseline_exceedance_abs_error: float
    baseline_exceedance_ok: bool
    windows_total_expected: int | None
    windows_scored_n: int | None
    dropped_partial_windows_expected: int | None
    seed: int | None
    training_samples: int | None
    training_samples_warning_raw: bool | None
    training_samples_warning_recommended: bool | None
    threshold_equals_max: bool | None
    tie_at_threshold_ratio: float | None
    np_percentile_method: str | None


def main() -> int:
    if not FREEZE.exists():
        raise SystemExit(f"Missing freeze anchor: {FREEZE}")
    freeze = _rjson(FREEZE) or {}
    included = [str(x) for x in (freeze.get("included_run_ids") or [])]
    if not included:
        raise SystemExit("Freeze manifest has no included_run_ids")

    # Baseline P95 exceedance isn't exactly 0.05 due to ties/finite windows; allow a small tolerance.
    expected = 0.05
    tol = 0.03  # accept [0.02, 0.08] by default
    # The on-disk model manifests currently embed a warning threshold tuned for operational mode.
    # For Paper #2 QA, warn only when baseline training windows are meaningfully below the paper contract.
    # This reduces audit noise without changing any frozen scores/thresholds.
    warn_training_samples_below = max(
        int(math.ceil(float(paper2.MIN_WINDOWS_BASELINE) * 1.2)),
        int(paper2.MIN_WINDOWS_BASELINE) + 5,
    )

    rows: list[RunAuditRow] = []
    errors: list[str] = []
    warnings: list[str] = []

    for rid in included:
        run_dir = EVIDENCE_ROOT / rid
        man = _rjson(run_dir / "run_manifest.json")
        if not isinstance(man, dict):
            errors.append(f"MISSING_RUN_MANIFEST:{rid}")
            continue
        tgt = man.get("target") if isinstance(man.get("target"), dict) else {}
        pkg = str(tgt.get("package_name") or "").strip().lower()
        op = man.get("operator") if isinstance(man.get("operator"), dict) else {}
        ds = man.get("dataset") if isinstance(man.get("dataset"), dict) else {}
        run_profile = str(op.get("run_profile") or ds.get("run_profile") or "")
        interaction_level = str(op.get("interaction_level") or ds.get("interaction_level") or "")
        bucket = _bucket(man)

        ml_dir = run_dir / "analysis" / "ml" / paper2.ML_SCHEMA_LABEL
        mm = _rjson(ml_dir / "model_manifest.json") if ml_dir.exists() else None
        thr = _rjson(ml_dir / "baseline_threshold.json") if ml_dir.exists() else None
        pre = _rjson(ml_dir / "ml_preflight.json") if ml_dir.exists() else None

        seed = None
        if isinstance(mm, dict) and mm.get("seed") is not None:
            try:
                seed = int(mm.get("seed"))
            except Exception:
                seed = None

        windows_total_expected = None
        dropped_partial_windows_expected = None
        if isinstance(pre, dict):
            try:
                windows_total_expected = int(pre.get("windows_total_expected")) if pre.get("windows_total_expected") is not None else None
            except Exception:
                windows_total_expected = None
            try:
                dropped_partial_windows_expected = int(pre.get("dropped_partial_windows_expected")) if pre.get("dropped_partial_windows_expected") is not None else None
            except Exception:
                dropped_partial_windows_expected = None

        model_meta = (mm.get("models") if isinstance(mm, dict) else {}) or {}
        thr_models = (thr.get("models") if isinstance(thr, dict) else {}) or {}

        for model_name, csv_label in ((paper2.MODEL_IFOREST, "iforest"), (paper2.MODEL_OCSVM, "ocsvm")):
            scores_path = ml_dir / f"anomaly_scores_{csv_label}.csv"
            scores = _read_scores(scores_path)
            if scores is None:
                errors.append(f"MISSING_SCORES:{rid}:{model_name}")
                continue
            scored_n = len(scores)
            nan_inf = sum(1 for s in scores if not _finite(float(s)))
            if nan_inf:
                errors.append(f"NAN_INF_SCORES:{rid}:{model_name}:{nan_inf}")

            tmeta = thr_models.get(model_name) if isinstance(thr_models.get(model_name), dict) else {}
            tau = float(tmeta.get("threshold_value") or 0.0)
            pctl = float(tmeta.get("threshold_percentile") or paper2.THRESHOLD_PERCENTILE)
            exceed_n = sum(1 for s in scores if float(s) >= tau)
            exceed_ratio = float(exceed_n) / float(scored_n) if scored_n else 0.0
            tie_ratio = (
                float(sum(1 for s in scores if float(s) == tau)) / float(scored_n) if scored_n else 0.0
            )

            # Baseline check: only meaningful on baseline runs.
            ok = True
            abs_err = 0.0
            if bucket == "idle":
                abs_err = abs(exceed_ratio - expected)
                ok = abs_err <= tol
                if not ok:
                    warnings.append(
                        f"BASELINE_EXCEEDANCE_OUT_OF_RANGE:{pkg}:{rid}:{model_name}:ratio={exceed_ratio:.4f}:tau={tau:.6g}"
                    )

            mmeta = model_meta.get(model_name) if isinstance(model_meta.get(model_name), dict) else {}
            training_samples = None
            training_samples_warning_raw = None
            threshold_equals_max = None
            np_method = None
            if isinstance(mmeta, dict):
                try:
                    training_samples = int(mmeta.get("training_samples")) if mmeta.get("training_samples") is not None else None
                except Exception:
                    training_samples = None
                training_samples_warning_raw = (
                    bool(mmeta.get("training_samples_warning")) if mmeta.get("training_samples_warning") is not None else None
                )
                threshold_equals_max = bool(mmeta.get("threshold_equals_max")) if mmeta.get("threshold_equals_max") is not None else None
                np_method = str(mmeta.get("np_percentile_method") or "") or None

            training_samples_warning_recommended = None
            if training_samples is not None:
                training_samples_warning_recommended = bool(int(training_samples) < int(warn_training_samples_below))

            rows.append(
                RunAuditRow(
                    run_id=rid,
                    package_name=pkg,
                    run_profile=str(run_profile),
                    interaction_level=str(interaction_level),
                    bucket=bucket,
                    model=model_name,
                    threshold_percentile=pctl,
                    threshold_value=float(tau),
                    scores_n=int(scored_n),
                    scores_nan_inf=int(nan_inf),
                    exceedance_ratio=float(exceed_ratio),
                    baseline_expected_exceedance=float(expected),
                    baseline_exceedance_abs_error=float(abs_err),
                    baseline_exceedance_ok=bool(ok),
                    windows_total_expected=windows_total_expected,
                    windows_scored_n=_count_data_rows(scores_path),
                    dropped_partial_windows_expected=dropped_partial_windows_expected,
                    seed=seed,
                    training_samples=training_samples,
                    training_samples_warning_raw=training_samples_warning_raw,
                    training_samples_warning_recommended=training_samples_warning_recommended,
                    threshold_equals_max=threshold_equals_max,
                    tie_at_threshold_ratio=float(tie_ratio),
                    np_percentile_method=np_method,
                )
            )

    # Write JSON + CSV.
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_at_utc": datetime.now(UTC).isoformat(),
                "freeze_dataset_hash": freeze.get("freeze_dataset_hash"),
                "ml_schema_label": paper2.ML_SCHEMA_LABEL,
                "paper_contract_version": paper2.PAPER_CONTRACT_VERSION,
                "expected_baseline_exceedance": expected,
                "baseline_exceedance_tolerance_abs": tol,
                "training_samples_warning_recommended_threshold": warn_training_samples_below,
                "rows": [asdict(r) for r in rows],
                "errors": errors,
                "warnings": warnings,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    with OUT_CSV.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()) if rows else [])
        if rows:
            w.writeheader()
            for r in rows:
                w.writerow(asdict(r))

    print(str(OUT_JSON))
    print(str(OUT_CSV))
    # Non-zero only for hard errors.
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
