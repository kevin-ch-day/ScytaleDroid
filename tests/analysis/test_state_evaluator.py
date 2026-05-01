from datetime import UTC, datetime, timedelta

from scytaledroid.DynamicAnalysis.analysis.state_evaluator import WindowFeatures, evaluate_state


def test_state_evaluator_idle():
    now = datetime.now(UTC)
    features = WindowFeatures(
        window_start=now,
        window_end=now + timedelta(seconds=10),
        bytes_in=100,
        bytes_out=50,
        cpu_pct=1.0,
        mem_kb=100_000,
        burstiness=0.1,
        duty_cycle=0.1,
        periodicity=0.1,
        uplink_ratio=0.2,
    )
    decision = evaluate_state(features, cross_source_score=0.8, reproducible=True)
    assert decision.state in {"idle", "uncertain"}
    assert decision.evidence.rules_fired
