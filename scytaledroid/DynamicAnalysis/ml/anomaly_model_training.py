"""Model wrappers for Paper #2 ML (fixed params, deterministic)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from . import ml_parameters_profile as config


@dataclass(frozen=True)
class ModelSpec:
    name: str
    params: dict[str, Any]


def fixed_model_specs(seed: int, *, ml_config=config) -> list[ModelSpec]:
    """Return model specs for the active ML config.

    Paper mode keeps locked defaults; operational mode can override via
    ml_parameters_operational without changing call sites.
    """
    iforest_name = str(getattr(ml_config, "MODEL_IFOREST", config.MODEL_IFOREST))
    ocsvm_name = str(getattr(ml_config, "MODEL_OCSVM", config.MODEL_OCSVM))
    return [
        ModelSpec(
            name=iforest_name,
            params={
                "n_estimators": int(getattr(ml_config, "IFOREST_N_ESTIMATORS", 200)),
                "max_samples": getattr(ml_config, "IFOREST_MAX_SAMPLES", "auto"),
                "contamination": "auto",  # thresholding is percentile-based, not this field
                "bootstrap": bool(getattr(ml_config, "IFOREST_BOOTSTRAP", False)),
                "random_state": seed,
            },
        ),
        ModelSpec(
            name=ocsvm_name,
            params={
                "kernel": str(getattr(ml_config, "OCSVM_KERNEL", "rbf")),
                "nu": float(getattr(ml_config, "OCSVM_NU", 0.05)),
                "gamma": getattr(ml_config, "OCSVM_GAMMA", "scale"),
                "shrinking": bool(getattr(ml_config, "OCSVM_SHRINKING", False)),
                "tol": float(getattr(ml_config, "OCSVM_TOL", 1e-3)),
            },
        ),
    ]


def fit_model(spec: ModelSpec, X: np.ndarray):
    # sklearn is an optional dependency for some operators (and can be broken in some environments).
    # Import it lazily so non-ML workflows don't fail at import time.
    if spec.name == config.MODEL_IFOREST:
        try:
            from sklearn.ensemble import IsolationForest  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"SKLEARN_UNAVAILABLE:IsolationForest:{type(exc).__name__}") from exc
        model = IsolationForest(**spec.params)
        model.fit(X)
        return model
    if spec.name == config.MODEL_OCSVM:
        try:
            from sklearn.svm import OneClassSVM  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"SKLEARN_UNAVAILABLE:OneClassSVM:{type(exc).__name__}") from exc
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
