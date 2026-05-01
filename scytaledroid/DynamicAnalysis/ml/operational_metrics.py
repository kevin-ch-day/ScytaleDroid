"""Operational (Phase F2) derived metrics.

These metrics are *post-hoc* summaries computed from window-level outputs.
They do not change Phase E (paper) semantics and are intended for:
- stability/confidence reporting as N runs grows
- persistence vs. spiky deviation characterisation
- lightweight interaction intensity inference (heuristic)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from .numpy_percentile import percentile as np_percentile
from .telemetry_windowing import WindowSpec


def anomaly_streaks(is_anomalous: list[bool]) -> tuple[int, int]:
    """Return (streak_count, longest_streak) over a boolean anomaly sequence."""
    streak = 0
    longest = 0
    streaks = 0
    for v in is_anomalous:
        if v:
            streak += 1
            longest = max(longest, streak)
        else:
            if streak:
                streaks += 1
            streak = 0
    if streak:
        streaks += 1
    return streaks, longest


def persistence_seconds(longest_streak: int, *, spec: WindowSpec) -> float:
    """Approximate persistence duration for a longest-streak length under overlap windowing.

    With window_size=W and stride=S, k consecutive anomalous windows implies coverage:
      duration ~= W + (k-1)*S
    """
    if longest_streak <= 0:
        return 0.0
    return float(spec.window_size_s) + float(max(0, longest_streak - 1)) * float(spec.stride_s)


def threshold_stability(scores_train: np.ndarray, threshold: float, *, np_method: str) -> dict[str, Any]:
    """Summarise training distribution for threshold stability diagnostics."""
    if scores_train.size == 0:
        return {"training_samples": 0}
    arr = np.asarray(scores_train, dtype=float).reshape(-1)
    n = int(arr.shape[0])
    s_min = float(np.min(arr))
    s_max = float(np.max(arr))
    s_med = float(np.median(arr))
    p95 = float(np_percentile(arr, 95.0, method=np_method))
    p99 = float(np_percentile(arr, 99.0, method=np_method))
    q1 = float(np_percentile(arr, 25.0, method=np_method))
    q3 = float(np_percentile(arr, 75.0, method=np_method))
    iqr = float(max(q3 - q1, 1e-12))
    thr = float(threshold)
    # Normalised distance to max; small values mean "threshold near max".
    denom = float(max(s_max - s_min, 1e-12))
    thr_to_max_norm = float((s_max - thr) / denom)
    thr_equals_max = bool(abs(thr - s_max) <= 1e-9)
    thr_near_max = bool(thr_to_max_norm <= 0.05)
    return {
        "training_samples": n,
        "train_min": s_min,
        "train_median": s_med,
        "train_p95": p95,
        "train_p99": p99,
        "train_max": s_max,
        "train_q1": q1,
        "train_q3": q3,
        "train_iqr": iqr,
        "threshold_value": thr,
        "threshold_equals_max": thr_equals_max,
        "threshold_near_max": thr_near_max,
        "threshold_to_max_norm": thr_to_max_norm,
    }


@dataclass(frozen=True)
class IntensityInference:
    score: float | None
    label: str
    details: dict[str, Any]


def infer_intensity_from_windows(
    *,
    run_window_rows: list[dict[str, Any]],
    baseline_p95_bytes_per_sec: float | None,
    spec: WindowSpec,
) -> IntensityInference:
    """Heuristic run intensity inference from network window features.

    Uses per-window bytes_per_sec computed from byte_count and window size, and compares
    the run's p95 bytes/sec to the baseline p95 bytes/sec for the group when available.
    """
    denom = float(spec.window_size_s) if spec.window_size_s > 0 else 1.0
    bps: list[float] = []
    for r in run_window_rows:
        try:
            bps.append(float(r.get("byte_count") or 0.0) / denom)
        except Exception:
            continue
    if not bps:
        return IntensityInference(score=None, label="unknown", details={"reason": "no_windows"})

    arr = np.asarray(bps, dtype=float)
    run_p95 = float(np_percentile(arr, 95.0, method="linear"))
    run_med = float(np.median(arr))
    base = float(baseline_p95_bytes_per_sec) if baseline_p95_bytes_per_sec is not None else None
    if base is None or base <= 0.0:
        # No baseline: fall back to absolute-ish scale (still heuristic).
        if run_p95 < 50_000:
            return IntensityInference(score=None, label="light", details={"run_p95_bps": run_p95, "run_med_bps": run_med})
        if run_p95 < 250_000:
            return IntensityInference(score=None, label="medium", details={"run_p95_bps": run_p95, "run_med_bps": run_med})
        return IntensityInference(score=None, label="heavy", details={"run_p95_bps": run_p95, "run_med_bps": run_med})

    ratio = float(run_p95 / base) if base > 0 else 0.0
    # Keep bins simple and explainable; this is an operational hint, not a paper claim.
    if ratio <= 1.25:
        label = "light"
    elif ratio <= 2.5:
        label = "medium"
    else:
        label = "heavy"
    return IntensityInference(
        score=ratio,
        label=label,
        details={"run_p95_bps": run_p95, "run_med_bps": run_med, "baseline_p95_bps": base, "ratio": ratio},
    )
