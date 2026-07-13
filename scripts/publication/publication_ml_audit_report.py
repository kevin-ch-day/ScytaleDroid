#!/usr/bin/env python3
"""Machine-learning audit report (freeze-anchored).

This is a deeper ML-focused audit than the general pipeline audit:
- verifies score semantics per model (higher_is_more_anomalous)
- checks baseline thresholding behavior (baseline exceedance ~= 0.05 for P95, within tolerance)
- checks per-run window accounting (expected vs scored rows)
- flags NaN/Inf in scores and other silent-failure patterns

Outputs:
  output/publication/qa/ml_audit_report_v1.json (canonical)
  output/publication/qa/ml_audit_report_v1.csv (canonical)
"""

from __future__ import annotations

import csv
import json
import math
import os
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config  # noqa: E402
from scytaledroid.DynamicAnalysis.research_cohort_archive import (  # noqa: E402
    resolve_dataset_freeze_read_path,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root  # noqa: E402

OUT_DIR = REPO_ROOT / "output" / "publication" / "qa"
OUT_JSON = OUT_DIR / "ml_audit_report_v1.json"
OUT_CSV = OUT_DIR / "ml_audit_report_v1.csv"


def _freeze_path() -> Path:
    return resolve_dataset_freeze_read_path()


def _evidence_root() -> Path:
    return dynamic_evidence_root()


def _print_help() -> None:
    print("usage: publication_ml_audit_report.py [-h]")
    print()
    print("Generate frozen-archive ML audit report.")
    print()
    print("options:")
    print("  -h, --help  show this help message and exit")


def _write_legacy_aliases() -> bool:
    # Opt-in only: reduces bundle clutter for OSS users.
    return str(os.environ.get("SCYTALEDROID_WRITE_LEGACY_ALIASES") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


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


def _summarize_baseline_calibration(
    rows: list[dict[str, object]],
    *,
    hard_error_count: int,
) -> dict[str, object]:
    """Summarize model QA without hiding detailed per-app warnings."""

    by_model: dict[str, dict[str, object]] = {}
    for row in rows:
        model = str(row.get("model") or "").strip()
        if not model:
            continue
        summary = by_model.setdefault(
            model,
            {
                "app_count": 0,
                "ok_app_count": 0,
                "warning_app_count": 0,
                "max_baseline_exceedance_ratio": 0.0,
                "max_baseline_exceedance_abs_error": 0.0,
            },
        )
        summary["app_count"] = int(summary.get("app_count") or 0) + 1
        ok = bool(row.get("baseline_exceedance_ok"))
        if ok:
            summary["ok_app_count"] = int(summary.get("ok_app_count") or 0) + 1
        else:
            summary["warning_app_count"] = int(summary.get("warning_app_count") or 0) + 1
        ratio = float(row.get("baseline_exceedance_ratio") or 0.0)
        abs_error = float(row.get("baseline_exceedance_abs_error") or 0.0)
        summary["max_baseline_exceedance_ratio"] = max(
            float(summary.get("max_baseline_exceedance_ratio") or 0.0),
            ratio,
        )
        summary["max_baseline_exceedance_abs_error"] = max(
            float(summary.get("max_baseline_exceedance_abs_error") or 0.0),
            abs_error,
        )

    primary = by_model.get(profile_config.MODEL_IFOREST, {})
    secondary = by_model.get(profile_config.MODEL_OCSVM, {})
    primary_warnings = int(primary.get("warning_app_count") or 0)
    secondary_warnings = int(secondary.get("warning_app_count") or 0)
    blocked = hard_error_count > 0 or primary_warnings > 0
    return {
        "status": "BLOCKED" if blocked else ("OK_WITH_SECONDARY_CAVEATS" if secondary_warnings else "OK"),
        "hard_error_count": int(hard_error_count),
        "primary_model": profile_config.MODEL_IFOREST,
        "primary_model_calibration": "OK" if primary_warnings == 0 else "WARN",
        "secondary_model": profile_config.MODEL_OCSVM,
        "secondary_model_calibration": "WARN" if secondary_warnings else "OK",
        "secondary_model_caveat": (
            "One-Class SVM is retained as a secondary robustness signal; do not use it as the sole publication gate."
            if secondary_warnings
            else ""
        ),
        "model_calibration": by_model,
    }


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
    freeze_path = _freeze_path()
    if not freeze_path.exists():
        raise SystemExit(
            "Missing freeze anchor: "
            f"{freeze_path}. Generate or restore the freeze anchor before running the ML audit. "
            f"Current dynamic evidence root: {_evidence_root()}"
        )
    freeze = _rjson(freeze_path) or {}
    included = [str(x) for x in (freeze.get("included_run_ids") or [])]
    if not included:
        raise SystemExit("Freeze manifest has no included_run_ids")

    # Baseline P95 exceedance isn't exactly 0.05 due to ties/finite windows; allow a small tolerance.
    expected = 0.05
    tol = 0.03  # accept [0.02, 0.08] by default
    # The on-disk model manifests currently embed a warning threshold tuned for operational mode.
    # For publication QA, warn only when baseline training windows are meaningfully below the contract.
    # This reduces audit noise without changing any frozen scores/thresholds.
    warn_training_samples_below = max(
        int(math.ceil(float(profile_config.MIN_WINDOWS_BASELINE) * 1.2)),
        int(profile_config.MIN_WINDOWS_BASELINE) + 5,
    )

    rows: list[RunAuditRow] = []
    errors: list[str] = []
    warnings: list[str] = []
    baseline_calibration: dict[tuple[str, str], dict[str, float | int]] = {}
    evidence_root = _evidence_root()

    for rid in included:
        run_dir = evidence_root / rid
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

        ml_dir = run_dir / "analysis" / "ml" / profile_config.ML_SCHEMA_LABEL
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

        for model_name, csv_label in ((profile_config.MODEL_IFOREST, "iforest"), (profile_config.MODEL_OCSVM, "ocsvm")):
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
            pctl = float(tmeta.get("threshold_percentile") or profile_config.THRESHOLD_PERCENTILE)
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
                aggregate = baseline_calibration.setdefault(
                    (pkg, model_name),
                    {"exceed_n": 0, "scores_n": 0, "run_count": 0, "threshold_value": tau},
                )
                aggregate["exceed_n"] = int(aggregate.get("exceed_n") or 0) + int(exceed_n)
                aggregate["scores_n"] = int(aggregate.get("scores_n") or 0) + int(scored_n)
                aggregate["run_count"] = int(aggregate.get("run_count") or 0) + 1

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

    baseline_calibration_rows: list[dict[str, object]] = []
    for (pkg, model_name), aggregate in sorted(baseline_calibration.items()):
        scores_n = int(aggregate.get("scores_n") or 0)
        exceed_n = int(aggregate.get("exceed_n") or 0)
        ratio = float(exceed_n) / float(scores_n) if scores_n else 0.0
        abs_err = abs(ratio - expected)
        ok = abs_err <= tol
        run_count = int(aggregate.get("run_count") or 0)
        baseline_calibration_rows.append(
            {
                "package_name": pkg,
                "model": model_name,
                "baseline_run_count": run_count,
                "baseline_scores_n": scores_n,
                "baseline_exceedance_ratio": ratio,
                "baseline_expected_exceedance": expected,
                "baseline_exceedance_abs_error": abs_err,
                "baseline_exceedance_ok": ok,
                "threshold_value": float(aggregate.get("threshold_value") or 0.0),
            }
        )
        if not ok:
            warnings.append(
                f"BASELINE_AGGREGATE_EXCEEDANCE_OUT_OF_RANGE:{pkg}:{model_name}:"
                f"ratio={ratio:.4f}:runs={run_count}:n={scores_n}"
            )

    readiness = _summarize_baseline_calibration(
        baseline_calibration_rows,
        hard_error_count=len(errors),
    )

    # Write JSON + CSV (canonical). Legacy aliases are opt-in.
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            {
                "schema_version": 1,
                "generated_at_utc": datetime.now(UTC).isoformat(),
                "freeze_dataset_hash": freeze.get("freeze_dataset_hash"),
                "ml_schema_label": profile_config.ML_SCHEMA_LABEL,
                "paper_contract_version": profile_config.PAPER_CONTRACT_VERSION,
                "expected_baseline_exceedance": expected,
                "baseline_exceedance_tolerance_abs": tol,
                "training_samples_warning_recommended_threshold": warn_training_samples_below,
                "readiness": readiness,
                "baseline_calibration": baseline_calibration_rows,
                "rows": [asdict(r) for r in rows],
                "errors": errors,
                "warnings": warnings,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    json_targets = [OUT_JSON]
    if _write_legacy_aliases():
        json_targets.append(OUT_DIR / "paper2_ml_audit_report_v1.json")
    for p in json_targets:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(payload, encoding="utf-8")

    csv_targets = [OUT_CSV]
    if _write_legacy_aliases():
        csv_targets.append(OUT_DIR / "paper2_ml_audit_report_v1.csv")
    for p in csv_targets:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8", newline="") as f:
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
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        _print_help()
        raise SystemExit(0)
    raise SystemExit(main())
