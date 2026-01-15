"""Unsupervised anomaly scoring for behavior windows."""

from __future__ import annotations

from typing import Dict, List

import numpy as np

from scytaledroid.BehaviorAnalysis.features import FEATURE_HEADERS


def _feature_matrix(windows: List[Dict[str, object]]) -> np.ndarray:
    numeric_keys = [k for k in FEATURE_HEADERS if k not in {"window_start_utc", "window_end_utc", "uid", "marker_nearest"}]
    matrix = []
    for row in windows:
        vals = []
        for key in numeric_keys:
            val = row.get(key)
            try:
                vals.append(float(val))
            except Exception:
                vals.append(0.0)
        matrix.append(vals)
    return np.array(matrix, dtype=float), numeric_keys


def score_windows(windows: List[Dict[str, object]], *, backend_hint: str = "sklearn") -> List[Dict[str, object]]:
    if not windows:
        return []
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.svm import OneClassSVM
    except Exception:  # pragma: no cover - dependency fallback
        return _fallback_scores(windows)
    X, _ = _feature_matrix(windows)
    scores: List[Dict[str, object]] = []
    models = [
        ("IsolationForest", IsolationForest(contamination=0.02, random_state=42)),
        ("OneClassSVM", OneClassSVM(nu=0.02, kernel="rbf", gamma="scale")),
    ]
    for name, model in models:
        try:
            model.fit(X)
            raw_scores = model.decision_function(X)
            # Normalize so higher = more anomalous
            norm_scores = -raw_scores
            threshold = float(np.quantile(norm_scores, 0.98))
        except Exception:
            norm_scores = np.zeros(len(windows))
            threshold = 0.0
        for row, score in zip(windows, norm_scores):
            scores.append(
                {
                    "window_start_utc": row.get("window_start_utc", ""),
                    "window_end_utc": row.get("window_end_utc", ""),
                    "uid": row.get("uid", ""),
                    "model_name": name,
                    "model_backend": "sklearn",
                    "score": round(float(score), 6),
                    "is_anomaly": 1 if score >= threshold else 0,
                    "threshold": round(threshold, 6),
                    "score_direction": "higher_is_more_anomalous",
                    "marker_nearest": row.get("marker_nearest", ""),
                    "marker_delta_s": row.get("marker_delta_s", ""),
                }
            )
    return scores


def _fallback_scores(windows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    if not windows:
        return []
    scores: List[Dict[str, object]] = []
    composite: List[float] = []
    for row in windows:
        try:
            cpu = float(row.get("cpu_pct_mean") or 0.0)
            net = float(row.get("bytes_out_rate") or 0.0)
        except Exception:
            cpu = 0.0
            net = 0.0
        composite.append(cpu + net)
    arr = np.array(composite, dtype=float)
    threshold = float(np.quantile(arr, 0.98)) if len(arr) else 0.0
    for row, score in zip(windows, arr):
        scores.append(
            {
                "window_start_utc": row.get("window_start_utc", ""),
                "window_end_utc": row.get("window_end_utc", ""),
                "uid": row.get("uid", ""),
                "model_name": "CompositeQuantile",
                "model_backend": "fallback",
                "score": round(float(score), 6),
                "is_anomaly": 1 if score >= threshold else 0,
                "threshold": round(threshold, 6),
                "score_direction": "higher_is_more_anomalous",
                "marker_nearest": row.get("marker_nearest", ""),
                "marker_delta_s": row.get("marker_delta_s", ""),
            }
        )
    return scores
