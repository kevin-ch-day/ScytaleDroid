from __future__ import annotations


def test_numpy_percentile_wrapper_matches_explicit_method() -> None:
    import numpy as np
    from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as config
    from scytaledroid.DynamicAnalysis.ml.numpy_percentile import percentile

    arr = np.asarray([0.0, 1.0, 2.0, 3.0, 100.0], dtype=float)
    want = np.percentile(arr, 95.0, method=config.NP_PERCENTILE_METHOD)
    got = percentile(arr, 95.0, method=config.NP_PERCENTILE_METHOD)
    assert float(got) == float(want)

