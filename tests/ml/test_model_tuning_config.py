from __future__ import annotations

import numpy as np
from scytaledroid.DynamicAnalysis.ml import ml_parameters_operational as operational_config
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as paper_config
from scytaledroid.DynamicAnalysis.ml.anomaly_model_training import fixed_model_specs
from scytaledroid.DynamicAnalysis.ml.operational_risk import build_static_inputs_from_plan
from scytaledroid.DynamicAnalysis.ml.query_mode_runner import _apply_winsorization


def test_fixed_model_specs_paper_defaults() -> None:
    specs = fixed_model_specs(seed=7, ml_config=paper_config)
    by_name = {s.name: s for s in specs}
    if_spec = by_name[paper_config.MODEL_IFOREST]
    oc_spec = by_name[paper_config.MODEL_OCSVM]
    assert if_spec.params["n_estimators"] == 200
    assert if_spec.params["random_state"] == 7
    assert oc_spec.params["nu"] == 0.05


def test_fixed_model_specs_operational_overrides() -> None:
    specs = fixed_model_specs(seed=9, ml_config=operational_config)
    by_name = {s.name: s for s in specs}
    if_spec = by_name[operational_config.MODEL_IFOREST]
    oc_spec = by_name[operational_config.MODEL_OCSVM]
    assert if_spec.params["n_estimators"] == 300
    assert if_spec.params["random_state"] == 9
    assert oc_spec.params["nu"] == 0.03


def test_apply_winsorization_clips_with_train_bounds() -> None:
    x_train = np.asarray(
        [
            [1.0, 2.0, 3.0],
            [2.0, 3.0, 4.0],
            [3.0, 4.0, 5.0],
            [100.0, 200.0, 300.0],
        ],
        dtype=float,
    )
    x_all = np.asarray(
        [
            [0.0, 0.0, 0.0],
            [1000.0, 1000.0, 1000.0],
        ],
        dtype=float,
    )
    tr, all_, meta = _apply_winsorization(x_train, x_all, lower_pct=5.0, upper_pct=95.0)
    assert meta["method"] == "winsorize"
    lower = np.asarray(meta["lower"], dtype=float)
    upper = np.asarray(meta["upper"], dtype=float)
    assert np.all(tr >= lower)
    assert np.all(tr <= upper)
    assert np.all(all_ >= lower)
    assert np.all(all_ <= upper)


def test_build_static_inputs_prefers_static_features_snapshot() -> None:
    plan = {
        "static_features": {
            "exported_components_total": 21,
            "dangerous_permission_count": 9,
            "uses_cleartext_traffic": True,
            "sdk_indicator_score": 0.75,
        },
        "exported_components": {"total": 1},
        "permissions": {"dangerous": ["android.permission.CAMERA"]},
        "risk_flags": {"uses_cleartext_traffic": False},
        "sdk_indicators": {"score": 0.1},
    }
    out = build_static_inputs_from_plan(plan)
    assert out is not None
    assert out.exported_components_total == 21
    assert out.dangerous_permission_count == 9
    assert out.uses_cleartext_traffic == 1
    assert abs(out.sdk_indicator_score - 0.75) < 1e-9
