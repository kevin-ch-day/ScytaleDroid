from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.fingerprints import summarize_tls_fingerprints
from scytaledroid.DynamicAnalysis.pcap.posture import summarize_traffic_posture
from scytaledroid.DynamicAnalysis.pcap.transport_health import (
    _EVENT_FIELDS,
    summarize_transport_health,
)


def test_summarize_tls_fingerprints_counts_client_server_and_top_shares(
    monkeypatch, tmp_path: Path
) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")

    outputs = iter(
        [
            "ja3a\tja4a\th2\tapi.example.com\nja3a\tja4a\th2\tapi.example.com\nja3b\tja4b\th3\tcdn.example.com\n",
            "ja3sa\th2\nja3sb\th3\n",
        ]
    )

    class _Result:
        def __init__(self, stdout: str) -> None:
            self.returncode = 0
            self.stderr = ""
            self.stdout = stdout

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.fingerprints.subprocess.run",
        lambda *args, **kwargs: _Result(next(outputs)),
    )

    summary = summarize_tls_fingerprints(pcap_path, tshark_path="tshark", top_n=5)

    assert summary["client_hello_count"] == 3
    assert summary["server_hello_count"] == 2
    assert summary["unique_ja3_count"] == 2
    assert summary["unique_ja4_count"] == 2
    assert summary["unique_ja3s_count"] == 2
    assert summary["unique_alpn_count"] == 2
    assert summary["unique_sni_from_client_hello_count"] == 2
    assert summary["top_ja3"][0]["value"] == "ja3a"
    assert summary["top_ja3"][0]["count"] == 2
    assert summary["top1_ja3_share"] == 2.0 / 3.0
    assert summary["top1_ja4_share"] == 2.0 / 3.0
    assert summary["top1_ja3s_share"] == 0.5


def test_summarize_transport_health_counts_events_and_top_streams(
    monkeypatch, tmp_path: Path
) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    row_len = 1 + len(_EVENT_FIELDS) + 1 + 3
    rows = [["" for _ in range(row_len)] for _ in range(4)]
    rows[0][0] = "7"
    rows[0][1] = "1"
    rows[0][1 + len(_EVENT_FIELDS)] = "1"
    rows[0][1 + len(_EVENT_FIELDS) + 1] = "1"
    rows[0][1 + len(_EVENT_FIELDS) + 2] = "1"
    rows[1][0] = "7"
    rows[1][2] = "1"
    rows[1][1 + len(_EVENT_FIELDS) + 3] = "1"
    rows[2][0] = "9"
    rows[2][5] = "1"
    rows[2][1 + len(_EVENT_FIELDS) + 1] = "1"
    rows[3][0] = "9"
    rows[3][7] = "1"
    rows[3][1 + len(_EVENT_FIELDS) + 3] = "1"

    class _Result:
        returncode = 0
        stderr = ""
        stdout = "\n".join("\t".join(row) for row in rows) + "\n"

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.transport_health.subprocess.run",
        lambda *args, **kwargs: _Result(),
    )

    summary = summarize_transport_health(pcap_path, tshark_path="tshark")
    assert summary["tcp_packet_count"] == 4
    assert summary["issue_packet_count"] == 4
    assert summary["reset_packet_count"] == 1
    assert summary["event_counts"]["retransmission"] == 1
    assert summary["event_counts"]["fast_retransmission"] == 1
    assert summary["event_counts"]["duplicate_ack"] == 1
    assert summary["event_counts"]["zero_window"] == 1
    assert summary["affected_stream_count"] == 2
    assert summary["lifecycle_packet_counts"]["syn"] == 2
    assert summary["lifecycle_packet_counts"]["fin"] == 2
    assert summary["lifecycle_summary"]["stream_count"] == 2
    assert summary["lifecycle_summary"]["handshake_seen_stream_count"] == 2
    assert summary["lifecycle_summary"]["reset_stream_count"] == 1
    assert summary["lifecycle_summary"]["clean_close_stream_count"] == 1
    assert summary["lifecycle_summary"]["partial_stream_count"] == 0
    assert summary["top_streams"][0]["tcp_stream"] == "7"


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
        startup_summary={
            "startup_byte_share": 0.92,
            "startup_packet_share": 0.7,
            "post_start_median_bytes_per_min": 18000.0,
            "post_start_mean_bytes_per_min": 22000.0,
            "startup_dominant": True,
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
    assert summary["startup_byte_share"] == 0.92
    assert summary["startup_packet_share"] == 0.7
    assert summary["post_start_median_bytes_per_min"] == 18000.0
    assert summary["post_start_mean_bytes_per_min"] == 22000.0
    assert summary["startup_dominant"] is True
