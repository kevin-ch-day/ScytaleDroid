from __future__ import annotations

from scytaledroid.DynamicAnalysis.pcap.posture import summarize_traffic_posture


def test_summarize_traffic_posture_derives_ratios_and_density() -> None:
    summary = summarize_traffic_posture(
        metrics={
            "packet_count": 100,
            "data_size_bytes": 1000,
            "capture_duration_s": 20.0,
        },
        direction_summary={
            "outbound_packets": 60,
            "inbound_packets": 30,
            "unknown_packets": 10,
            "outbound_bytes": 700,
            "inbound_bytes": 250,
            "unknown_bytes": 50,
            "confidence_counts": {"high": 50, "medium": 25, "unknown": 25},
        },
        flow_summary={
            "median_packets_per_flow": 8.0,
            "median_bytes_per_flow": 120.0,
            "top_flows": [{"packets": 40, "bytes": 500}],
        },
        burst_summary={
            "active_second_count": 12,
            "burst_count": 4,
        },
        visibility_summary={
            "tls_handshake_packets": 6,
        },
    )

    assert summary["outbound_packet_ratio"] == 0.6
    assert summary["inbound_packet_ratio"] == 0.3
    assert summary["outbound_byte_ratio"] == 0.7
    assert summary["inbound_byte_ratio"] == 0.25
    assert summary["direction_confident_packet_ratio"] == 0.75
    assert summary["active_second_ratio"] == 0.6
    assert summary["bursts_per_min"] == 12.0
    assert summary["median_packets_per_flow"] == 8.0
    assert summary["median_bytes_per_flow"] == 120.0
    assert summary["top_flow_packet_share"] == 0.4
    assert summary["top_flow_byte_share"] == 0.5
    assert summary["tls_handshakes_per_min"] == 18.0
