from datetime import UTC, datetime

from scytaledroid.DynamicAnalysis.analysis.probe_policy import select_adaptive_probes


def test_probe_policy_uncertainty():
    probes = select_adaptive_probes(
        uncertainty_score=0.5,
        heartbeat_vs_sync_threshold=0.2,
        novel_mode_detected=False,
        now=datetime.now(UTC),
    )
    assert probes
