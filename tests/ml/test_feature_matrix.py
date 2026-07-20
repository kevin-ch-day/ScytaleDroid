from __future__ import annotations

import numpy as np
from scytaledroid.DynamicAnalysis.ml.feature_matrix import BASIC_FEATURE_NAMES, rows_to_basic_matrix
from scytaledroid.DynamicAnalysis.ml.profile_v3_ml_derive import _rows_to_matrix_v3
from scytaledroid.DynamicAnalysis.ml.telemetry_windowing import WindowSpec


def test_rows_to_basic_matrix_preserves_v1_feature_contract() -> None:
    rows = [
        {"byte_count": 1_000, "packet_count": 10, "avg_packet_size_bytes": 100},
        {"byte_count": 500, "packet_count": 5, "avg_packet_size_bytes": 100},
    ]

    matrix, names = rows_to_basic_matrix(rows, window_spec=WindowSpec(window_size_s=10.0, stride_s=5.0))

    assert names == list(BASIC_FEATURE_NAMES)
    assert matrix.tolist() == [[100.0, 1.0, 100.0], [50.0, 0.5, 100.0]]


def test_rows_to_basic_matrix_applies_optional_log_transform() -> None:
    rows = [{"byte_count": 1_000, "packet_count": 10, "avg_packet_size_bytes": 100}]

    matrix, names = rows_to_basic_matrix(
        rows,
        window_spec=WindowSpec(window_size_s=10.0, stride_s=5.0),
        feature_log1p=True,
    )

    assert names == list(BASIC_FEATURE_NAMES)
    assert matrix.shape == (1, 3)
    assert np.isclose(matrix[0, 0], np.log1p(100.0))
    assert np.isclose(matrix[0, 1], np.log1p(1.0))
    assert matrix[0, 2] == 100.0


def test_profile_v3_matrix_uses_shared_v1_contract() -> None:
    spec = WindowSpec(window_size_s=10.0, stride_s=5.0)
    rows = [{"byte_count": 1_000, "packet_count": 10, "avg_packet_size_bytes": 100}]

    expected, expected_names = rows_to_basic_matrix(rows, window_spec=spec)
    actual, actual_names = _rows_to_matrix_v3(rows, window_spec=spec)

    assert actual_names == expected_names
    assert actual.tolist() == expected.tolist()
