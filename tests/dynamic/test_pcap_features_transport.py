from __future__ import annotations

from scytaledroid.DynamicAnalysis.pcap.features import _extract_features, PcapFeatureConfig


def test_pcap_features_include_intensity_and_transport_ratios() -> None:
    report = {
        "report_status": "ok",
        "missing_tools": [],
        "capinfos": {
            "parsed": {
                "packet_count": 100,
                "data_size_bytes": 1000,
                "capture_duration_s": 10.0,
                "avg_packet_rate_pps": 10.0,
            }
        },
        "protocol_hierarchy": [
            {"protocol": "ip", "bytes": 1000, "frames": 100},
            {"protocol": "tcp", "bytes": 800, "frames": 80},
            {"protocol": "udp", "bytes": 200, "frames": 20},
            {"protocol": "tls", "bytes": 400, "frames": 40},
            {"protocol": "quic", "bytes": 100, "frames": 10},
        ],
        "top_sni": [{"value": "a.example.com", "count": 1}],
        "top_dns": [{"value": "b.example.com", "count": 1}],
    }
    out = _extract_features(report, PcapFeatureConfig(), operator={"run_profile": "interactive_use"}, target={})
    # Versioned feature contract: schema version may be emitted at the top level.
    assert {"metrics", "proxies", "quality"}.issubset(set(out.keys()))
    metrics = out["metrics"]
    proxies = out["proxies"]
    quality = out["quality"]

    assert metrics["bytes_per_sec"] == 100.0
    assert metrics["packets_per_sec"] == 10.0
    assert proxies["tcp_ratio"] == 0.8
    assert proxies["udp_ratio"] == 0.2
    assert proxies["quic_ratio"] == 0.5
    assert proxies["tls_ratio"] == 0.5
    assert proxies["unique_domains_topn"] == 2
    assert quality["pcap_valid"] is True
