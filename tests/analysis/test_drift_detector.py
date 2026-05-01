from scytaledroid.DynamicAnalysis.analysis.drift_detector import detect_drift


def test_drift_detector_sustained():
    decision = detect_drift(
        baseline_dist=[0.9, 0.1],
        current_dist=[0.2, 0.8],
        state_proportions_js=0.2,
        js_threshold=0.1,
        wasserstein_threshold=0.05,
    )
    assert decision.decision in {"sustained", "rebaseline_candidate"}
