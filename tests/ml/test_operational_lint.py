from __future__ import annotations

import csv
import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.operational_lint import lint_operational_snapshot


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_operational_lint_surfaces_design_caveats_without_failing(tmp_path: Path) -> None:
    snap = tmp_path / "output" / "operational" / "query-test"
    tables = snap / "tables"
    group = "com.example.app"
    model = "one_class_svm"
    _write_csv(
        tables / "coverage_confidence_per_group.csv",
        [
            {
                "group_key": group,
                "package_name": group,
                "baseline_runs": 1,
                "training_mode": "union_fallback",
                "confidence_level": "low",
                "confidence_notes": "union_fallback",
            }
        ],
    )
    _write_csv(
        tables / "threshold_stability_per_group_model.csv",
        [
            {
                "group_key": group,
                "model": model,
                "threshold_value": 0.5,
                "train_min": 0.0,
                "train_max": 1.0,
                "train_p95": 0.5,
            }
        ],
    )
    _write_csv(
        tables / "dynamic_math_audit_per_group_model.csv",
        [
            {
                "group_key": group,
                "model": model,
                "interactive_anomalous_pct": 0.25,
                "deviation_grade": "Low",
                "dynamic_deviation_score": 25.0,
            }
        ],
    )
    _write_csv(
        tables / "risk_summary_per_group.csv",
        [
            {
                "group_key": group,
                "package_name": group,
                "exposure_grade": "Low",
                "deviation_grade_if": "Low",
                "final_regime_if": "Low Exposure + Low Deviation",
                "final_grade_if": "Low",
                "dynamic_deviation_score_if": 25.0,
                "dynamic_deviation_score_oc": 20.0,
                "static_exposure_score": 10.0,
            }
        ],
    )
    _write_csv(
        tables / "anomaly_persistence_per_run.csv",
        [
            {
                "group_key": group,
                "run_id": "run-1",
                "model": model,
                "windows_total": 4,
                "anomalous_windows": 1,
                "anomalous_pct": 0.25,
            }
        ],
    )
    _write_csv(
        tables / "anomaly_prevalence_per_group_mode.csv",
        [
            {
                "group_key": group,
                "model": model,
                "mode": "interactive",
                "windows_total": 4,
                "anomalous_windows": 1,
                "anomalous_pct": 0.25,
            }
        ],
    )
    _write_json(
        snap / "model_registry.json",
        {"models": [{"group_key": group, "model": model, "training_mode": "union_fallback"}]},
    )
    _write_json(
        snap / "freeze_manifest.json",
        {"duplicate_identity_groups": [{"identity": {"package_name_lc": group}, "run_ids": ["a", "b"]}]},
    )
    _write_json(snap / "snapshot_summary.json", {"freeze_ok": True})

    result = lint_operational_snapshot(snap)

    assert result.ok is True
    assert result.issues == []
    assert "duplicate_build_observations:1" in result.warnings
    assert f"fallback_training:{group}:union_fallback" in result.warnings
    assert f"low_confidence_group:{group}:union_fallback" in result.warnings
    assert f"ocsvm_fallback_training:{group}:union_fallback" in result.warnings
    assert f"thin_baseline:{group}:baseline_runs=1" in result.warnings

