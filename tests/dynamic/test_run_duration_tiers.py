from __future__ import annotations

from scytaledroid.DynamicAnalysis.run_duration_tiers import classify_duration_tier


def test_classify_duration_tier_boundaries() -> None:
    assert classify_duration_tier(None).key == "unknown"
    assert classify_duration_tier(179).key == "short"
    assert classify_duration_tier(180).key == "minimum"
    assert classify_duration_tier(239).key == "minimum"
    assert classify_duration_tier(240).key == "standard"
    assert classify_duration_tier(479).key == "standard"
    assert classify_duration_tier(480).key == "extended"
    assert classify_duration_tier(899).key == "extended"
    assert classify_duration_tier(900).key == "long_observation"
    assert classify_duration_tier(1799).key == "long_observation"
    assert classify_duration_tier(1800).key == "soak"
