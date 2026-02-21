from __future__ import annotations

from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import _compute_dars_v1


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
