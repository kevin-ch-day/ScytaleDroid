def test_pcap_features_protocol_ratios_clamped_and_case_normalized():
    from scytaledroid.DynamicAnalysis.pcap.features import PcapFeatureConfig, _extract_features

    report = {
        "report_status": "ok",
        "missing_tools": [],
        "capinfos": {"parsed": {"packet_count": 10, "data_size_bytes": 1000, "capture_duration_s": 10}},
        "top_sni": [],
        "top_dns": [],
        # Duplicate/case-mixed protocol rows (as tshark can emit).
        "protocol_hierarchy": [
            {"protocol": "IP", "frames": 1, "bytes": 100},
            {"protocol": "tcp", "frames": 1, "bytes": 80},
            {"protocol": "TLS", "frames": 1, "bytes": 90},  # slightly > tcp to test clamp
            {"protocol": "udp", "frames": 1, "bytes": 20},
            {"protocol": "quic", "frames": 1, "bytes": 25},  # slightly > udp to test clamp
            {"protocol": "gquic", "frames": 1, "bytes": 0},
        ],
    }

    features = _extract_features(report, PcapFeatureConfig(), operator={}, target={})
    proxies = features.get("proxies") or {}
    assert proxies.get("tcp_ratio") == 0.8
    assert proxies.get("udp_ratio") == 0.2
    # Clamped to [0, 1].
    assert proxies.get("tls_ratio") == 1.0
    assert proxies.get("quic_ratio") == 1.0

