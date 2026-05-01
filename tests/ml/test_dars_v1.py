from __future__ import annotations

import numpy as np

from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import _compute_dars_v1
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import _build_topk_and_zscores


def test_compute_dars_v1_basic() -> None:
    scores = [1.0, 2.0, 3.0, 4.0, 5.0]
    out = _compute_dars_v1(scores=scores, threshold=2.5)
    assert out["windows_total_n"] == 5
    assert out["operator"] == ">="
    assert out["k_policy"] == "ceil_10pct_windows"
    assert out["top_k"] == 1
    assert 0.0 <= float(out["exceedance_ratio"]) <= 1.0
    assert float(out["dars_v1"]) >= 0.0
    assert float(out["dars_v1"]) <= 100.0


def test_compute_dars_v1_empty() -> None:
    out = _compute_dars_v1(scores=[], threshold=1.0)
    assert out["windows_total_n"] == 0
    assert float(out["dars_v1"]) == 0.0


def test_compute_dars_v1_inclusive_threshold() -> None:
    out = _compute_dars_v1(scores=[1.0, 2.0, 2.0], threshold=2.0)
    assert abs(float(out["exceedance_ratio"]) - (2.0 / 3.0)) < 1e-6


def test_topk_rows_use_inclusive_exceedance() -> None:
    window_rows = [
        {"window_start_s": 0.0, "window_end_s": 10.0},
        {"window_start_s": 5.0, "window_end_s": 15.0},
    ]
    run_matrix = np.asarray([[1.0, 1.0, 1.0], [2.0, 2.0, 2.0]], dtype=float)
    scores = [1.5, 2.0]
    baseline_feature_stats = {
        "feature_names": ["bytes_per_sec", "packets_per_sec", "avg_packet_size_bytes"],
        "mu": [1.0, 1.0, 1.0],
        "sigma": [1.0, 1.0, 1.0],
    }
    topk_rows, _ = _build_topk_and_zscores(
        window_rows=window_rows,
        run_matrix=run_matrix,
        scores=scores,
        threshold=2.0,
        baseline_feature_stats=baseline_feature_stats,
        top_k=1,
    )
    assert topk_rows
    assert topk_rows[0]["score"] == 2.0
    assert topk_rows[0]["is_exceedance"] is True
