from __future__ import annotations

import numpy as np
from scytaledroid.DynamicAnalysis.ml.operational_metrics import (
    anomaly_streaks,
    infer_intensity_from_windows,
    persistence_seconds,
    threshold_stability,
)
from scytaledroid.DynamicAnalysis.ml.telemetry_windowing import WindowSpec


def test_anomaly_streaks_counts() -> None:
    assert anomaly_streaks([]) == (0, 0)
    assert anomaly_streaks([False, False]) == (0, 0)
    assert anomaly_streaks([True]) == (1, 1)
    assert anomaly_streaks([True, True, False, True]) == (2, 2)
    assert anomaly_streaks([False, True, False, True, True]) == (2, 2)


def test_persistence_seconds_overlap_windowing() -> None:
    spec = WindowSpec(window_size_s=10.0, stride_s=5.0)
    assert persistence_seconds(0, spec=spec) == 0.0
    assert persistence_seconds(1, spec=spec) == 10.0
    assert persistence_seconds(2, spec=spec) == 15.0
    assert persistence_seconds(3, spec=spec) == 20.0


def test_threshold_stability_basic_fields() -> None:
    arr = np.asarray([0.1, 0.2, 0.3, 0.4], dtype=float)
    out = threshold_stability(arr, 0.35, np_method="linear")
    assert out["training_samples"] == 4
    assert out["train_min"] == 0.1
    assert out["train_max"] == 0.4
    assert "threshold_to_max_norm" in out


def test_intensity_inference_ratio_bins() -> None:
    spec = WindowSpec(window_size_s=10.0, stride_s=5.0)
    # Run windows: byte_count -> bytes/sec = 100k.
    rows = [{"byte_count": 1_000_000} for _ in range(40)]
    inf = infer_intensity_from_windows(run_window_rows=rows, baseline_p95_bytes_per_sec=100_000, spec=spec)
    assert inf.label in {"light", "medium", "heavy"}
    # If baseline is much lower, should go heavy.
    inf2 = infer_intensity_from_windows(run_window_rows=rows, baseline_p95_bytes_per_sec=10_000, spec=spec)
    assert inf2.label == "heavy"

