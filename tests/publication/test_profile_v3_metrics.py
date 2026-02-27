from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from scytaledroid.Publication.profile_v3_metrics import (
    ProfileV3Error,
    compute_profile_v3_per_app,
    inspect_window_scores_schema,
    resolve_iforest_threshold,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_csv(path: Path, headers: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in headers})


def _mk_run(
    root: Path,
    run_id: str,
    *,
    package: str,
    run_profile: str,
    scores: list[float],
    threshold: float,
    engine_col: bool = True,
    engine_value: str = "iforest",
) -> None:
    run_dir = root / run_id
    _write_json(
        run_dir / "run_manifest.json",
        {
            "target": {"package_name": package},
            "operator": {"run_profile": run_profile},
            "environment": {"device_model": "moto", "android_version": "34", "build_fingerprint": "fp"},
        },
    )
    _write_json(run_dir / "analysis/ml/v1/baseline_threshold.json", {"threshold": threshold})
    headers = ["window_id", "score"]
    if engine_col:
        headers.append("engine_id")
    rows = []
    for i, s in enumerate(scores):
        r = {"window_id": i, "score": s}
        if engine_col:
            r["engine_id"] = engine_value
        rows.append(r)
    _write_csv(run_dir / "analysis/ml/v1/window_scores.csv", headers, rows)


def test_window_scores_schema_introspection(tmp_path: Path) -> None:
    p = tmp_path / "window_scores.csv"
    _write_csv(p, ["t0_index", "anomaly_score", "engine"], [{"t0_index": 0, "anomaly_score": 1.0, "engine": "iforest"}])
    schema = inspect_window_scores_schema(p)
    assert schema.score_col == "anomaly_score"
    assert schema.window_id_col == "t0_index"
    assert schema.engine_col == "engine"


def test_threshold_resolution_precedence() -> None:
    assert resolve_iforest_threshold({"threshold": 1.25}) == pytest.approx(1.25)
    assert resolve_iforest_threshold({"baseline_threshold": 2.0}) == pytest.approx(2.0)
    assert resolve_iforest_threshold({"thresholds": {"iforest": 3.0}}) == pytest.approx(3.0)
    assert resolve_iforest_threshold({"models": {"iforest": {"threshold": 4.0}}}) == pytest.approx(4.0)


def test_run_balanced_means_not_window_weighted(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    pkg = "com.example.app"
    catalog = {pkg: {"app": "Example", "app_category": "social_messaging"}}

    # Two idle runs with very different window counts/means:
    # idle_a: 10 windows, 20% flagged
    scores_a = [0.0] * 8 + [2.0] * 2
    _mk_run(evidence, "idle_a", package=pkg, run_profile="baseline_idle", scores=scores_a, threshold=1.0)
    # idle_b: 100 windows, 80% flagged
    scores_b = [0.0] * 20 + [2.0] * 80
    _mk_run(evidence, "idle_b", package=pkg, run_profile="baseline_idle", scores=scores_b, threshold=1.0)

    # One interactive run (50% flagged).
    scores_i = [0.0] * 50 + [2.0] * 50
    _mk_run(evidence, "int_a", package=pkg, run_profile="interaction_scripted", scores=scores_i, threshold=1.0)

    rows = compute_profile_v3_per_app(
        included_run_ids=["idle_a", "idle_b", "int_a"],
        evidence_root=evidence,
        catalog=catalog,
        allow_multi_model=False,
    )
    assert len(rows) == 1
    r = rows[0]
    # Run-balanced idle mean: (0.2 + 0.8)/2 = 0.5
    assert r.mu_idle_rdi == pytest.approx(0.5)


def test_exceedance_operator_is_strict_greater(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    pkg = "com.example.app"
    catalog = {pkg: {"app": "Example", "app_category": "social_messaging"}}

    # Score exactly at threshold should be unflagged for '>'.
    _mk_run(evidence, "idle", package=pkg, run_profile="baseline_idle", scores=[1.0, 1.0, 1.0, 1.0], threshold=1.0)
    _mk_run(evidence, "int", package=pkg, run_profile="interaction_scripted", scores=[2.0, 2.0, 2.0, 2.0], threshold=1.0)
    rows = compute_profile_v3_per_app(
        included_run_ids=["idle", "int"],
        evidence_root=evidence,
        catalog=catalog,
        allow_multi_model=False,
        allow_degenerate_metrics=True,
    )
    assert len(rows) == 1
    assert rows[0].mu_idle_rdi == pytest.approx(0.0)


def test_ddof_1_requires_at_least_two_idle_windows(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    pkg = "com.example.app"
    catalog = {pkg: {"app": "Example", "app_category": "social_messaging"}}

    # Single idle window -> pooled idle SD undefined (ddof=1) -> fail closed.
    _mk_run(evidence, "idle", package=pkg, run_profile="baseline_idle", scores=[0.0], threshold=1.0)
    _mk_run(evidence, "int", package=pkg, run_profile="interaction_scripted", scores=[2.0, 2.0], threshold=1.0)
    with pytest.raises(ProfileV3Error) as exc:
        compute_profile_v3_per_app(
            included_run_ids=["idle", "int"],
            evidence_root=evidence,
            catalog=catalog,
            allow_multi_model=False,
        )
    assert exc.value.code == "PROFILE_V3_INSUFFICIENT_WINDOWS_FOR_SD"


def test_manual_interaction_is_excluded_by_default(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    pkg = "com.example.app"
    catalog = {pkg: {"app": "Example", "app_category": "social_messaging"}}

    _mk_run(evidence, "idle", package=pkg, run_profile="baseline_idle", scores=[0.0, 0.0], threshold=1.0)
    _mk_run(evidence, "manual", package=pkg, run_profile="interaction_manual", scores=[2.0, 2.0], threshold=1.0)
    with pytest.raises(ProfileV3Error) as exc:
        compute_profile_v3_per_app(
            included_run_ids=["idle", "manual"],
            evidence_root=evidence,
            catalog=catalog,
            allow_multi_model=False,
        )
    assert exc.value.code == "PROFILE_V3_MANUAL_RUN_NOT_ALLOWED"


def test_degenerate_metrics_fail_closed_by_default(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    pkg = "com.example.app"
    catalog = {pkg: {"app": "Example", "app_category": "social_messaging"}}

    # All idle windows unflagged -> mu_idle=0 and sigma_idle=0 (degenerate).
    _mk_run(evidence, "idle", package=pkg, run_profile="baseline_idle", scores=[0.0, 0.0, 0.0, 0.0], threshold=1.0)
    _mk_run(evidence, "int", package=pkg, run_profile="interaction_scripted", scores=[2.0, 2.0, 2.0, 2.0], threshold=1.0)
    with pytest.raises(ProfileV3Error) as exc:
        compute_profile_v3_per_app(
            included_run_ids=["idle", "int"],
            evidence_root=evidence,
            catalog=catalog,
            allow_multi_model=False,
        )
    assert exc.value.code in {"PROFILE_V3_SIGMA_IDLE_ZERO", "PROFILE_V3_MU_IDLE_NONPOS"}


def test_degenerate_metrics_can_export_nulls_when_allowed(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    pkg = "com.example.app"
    catalog = {pkg: {"app": "Example", "app_category": "social_messaging"}}

    _mk_run(evidence, "idle", package=pkg, run_profile="baseline_idle", scores=[0.0, 0.0, 0.0, 0.0], threshold=1.0)
    _mk_run(evidence, "int", package=pkg, run_profile="interaction_scripted", scores=[2.0, 2.0, 2.0, 2.0], threshold=1.0)
    rows = compute_profile_v3_per_app(
        included_run_ids=["idle", "int"],
        evidence_root=evidence,
        catalog=catalog,
        allow_multi_model=False,
        allow_degenerate_metrics=True,
    )
    assert len(rows) == 1
    assert rows[0].isc is None
    assert rows[0].bsi is None


def test_run_profile_conflict_fails_closed(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    pkg = "com.example.app"
    catalog = {pkg: {"app": "Example", "app_category": "social_messaging"}}

    run_dir = evidence / "idle"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "target": {"package_name": pkg},
            "operator": {"run_profile": "baseline_idle"},
            "dataset": {"run_profile": "interaction_scripted"},
        },
    )
    _write_json(run_dir / "analysis/ml/v1/baseline_threshold.json", {"threshold": 1.0})
    _write_csv(
        run_dir / "analysis/ml/v1/window_scores.csv",
        ["window_id", "score", "engine_id"],
        [{"window_id": 0, "score": 0.0, "engine_id": "iforest"}, {"window_id": 1, "score": 0.0, "engine_id": "iforest"}],
    )
    _mk_run(evidence, "int", package=pkg, run_profile="interaction_scripted", scores=[2.0, 2.0], threshold=1.0)

    with pytest.raises(ProfileV3Error) as exc:
        compute_profile_v3_per_app(
            included_run_ids=["idle", "int"],
            evidence_root=evidence,
            catalog=catalog,
            allow_multi_model=False,
        )
    assert exc.value.code == "PROFILE_V3_RUN_PROFILE_CONFLICT"
