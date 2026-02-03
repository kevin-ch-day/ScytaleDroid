from scytaledroid.DynamicAnalysis.analysis.agreement import AgreementInputs, arbitrate


def test_arbitration_pcap_only():
    decision = arbitrate(
        AgreementInputs(
            lag_seconds=0.5,
            magnitude_ratio=0.9,
            pcap_present=True,
            netstats_present=False,
            cpu_pct=5.0,
        )
    )
    assert decision.decision == "pcap_only"
    assert "netstats_missing_use_pcap" in decision.reasons
