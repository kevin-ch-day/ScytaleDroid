"""Model wrappers for Paper #2 ML (fixed params, deterministic)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

from . import ml_parameters_paper2 as config


@dataclass(frozen=True)
class ModelSpec:
    name: str
    params: dict[str, Any]


def fixed_model_specs(seed: int) -> list[ModelSpec]:
    # Fixed params only. No tuning for Paper #2.
    return [
        ModelSpec(
            name=config.MODEL_IFOREST,
            params={
                "n_estimators": 200,
                "max_samples": "auto",
                "contamination": "auto",  # thresholding is percentile-based, not this field
                "bootstrap": False,
                "random_state": seed,
            },
        ),
        ModelSpec(
            name=config.MODEL_OCSVM,
            params={
                "kernel": "rbf",
                "nu": 0.05,
                "gamma": "scale",
                "shrinking": False,
                "tol": 1e-3,
            },
        ),
    ]


def fit_model(spec: ModelSpec, X: np.ndarray):
    if spec.name == config.MODEL_IFOREST:
        model = IsolationForest(**spec.params)
        model.fit(X)
        return model
    if spec.name == config.MODEL_OCSVM:
        model = OneClassSVM(**spec.params)
        model.fit(X)
        return model
    raise ValueError(f"Unknown model: {spec.name}")


def anomaly_scores(model_name: str, model, X: np.ndarray) -> np.ndarray:
    """Return anomaly score where higher means more anomalous."""
    if model_name == config.MODEL_IFOREST:
        # score_samples: higher is more normal -> invert.
        return -model.score_samples(X)
    if model_name == config.MODEL_OCSVM:
        # decision_function: higher is more normal -> invert.
        return -model.decision_function(X).reshape(-1)
    raise ValueError(f"Unknown model: {model_name}")
