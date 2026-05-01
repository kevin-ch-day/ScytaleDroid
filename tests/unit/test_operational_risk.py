from __future__ import annotations

from scytaledroid.DynamicAnalysis.ml.operational_risk import (
    dynamic_deviation_score_0_100,
    exposure_grade,
    final_posture_grade,
    final_posture_regime,
)


def test_exposure_grade_thresholds() -> None:
    assert exposure_grade(None) == "Unknown"
    assert exposure_grade(0.0) == "Low"
    assert exposure_grade(33.4) == "Medium"
    assert exposure_grade(66.7) == "High"


def test_dynamic_deviation_score_range_and_confidence() -> None:
    # p=0.1, L=0.1 => raw=0.1 => 10.0 under high confidence
    s_high = dynamic_deviation_score_0_100(
        anomalous_pct=0.1,
        longest_streak_windows=10,
        windows_total=100,
        confidence_level="high",
    )
    assert s_high == 10.0
    s_low = dynamic_deviation_score_0_100(
        anomalous_pct=0.1,
        longest_streak_windows=10,
        windows_total=100,
        confidence_level="low",
    )
    assert s_low == 6.0


def test_final_posture_regime_and_grade() -> None:
    reg = final_posture_regime(exposure_grade_label="High", deviation_grade_label="Low")
    assert reg == "High Exposure + Low Deviation"
    assert final_posture_grade(exposure_grade_label="Low", deviation_grade_label="Low") == "Low"
    assert final_posture_grade(exposure_grade_label="High", deviation_grade_label="High") == "High"
    assert final_posture_grade(exposure_grade_label="High", deviation_grade_label="Low") == "Medium"

