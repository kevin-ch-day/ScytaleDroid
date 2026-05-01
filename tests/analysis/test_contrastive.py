from scytaledroid.DynamicAnalysis.analysis.contrastive_testing import (
    evaluate_contrastive,
    js_divergence,
    wasserstein_distance,
)


def test_contrastive_evaluation():
    js = js_divergence([0.1, 0.9], [0.8, 0.2])
    w = wasserstein_distance([1, 2, 3], [10, 11, 12])
    result = evaluate_contrastive(
        js_value=js,
        wasserstein_value=w,
        effect_threshold=0.1,
        replication_ok=True,
        label="A vs B",
    )
    assert result.effect_size_pass
    assert "meaningful" in result.conclusion
