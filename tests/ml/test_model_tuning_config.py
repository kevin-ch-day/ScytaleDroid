from __future__ import annotations

import numpy as np

from scytaledroid.DynamicAnalysis.ml import ml_parameters_operational as operational_config
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as paper_config
from scytaledroid.DynamicAnalysis.ml.anomaly_model_training import fixed_model_specs
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

