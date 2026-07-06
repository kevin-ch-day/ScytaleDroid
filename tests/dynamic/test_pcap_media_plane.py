from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.media_plane import summarize_media_plane


def test_media_plane_detects_turn_backed_relay_media(monkeypatch, tmp_path: Path) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.media_plane._run_command",
        lambda cmd: {
            "stdout": "\n".join(
                [
                    "0x0003\t0x0003\t0x0000\t157.240.146.35\t3478",
                    "0x0103\t0x0003\t0x0010\t76.156.25.138\t43564",
                ]
            ),
            "stderr": "",
            "error": None,
        },
    )
    report = {
        "protocol_hierarchy_agg": {
            "bytes": {"ip": 44_000_000, "udp": 43_500_000, "quic": 44_000},
            "frames": {"ip": 47_000, "udp": 46_500, "stun": 480, "quic": 65},
        },
        "protocol_ratios": {"udp_ratio": 0.98, "tcp_ratio": 0.02, "tls_ratio": 0.0, "quic_ratio": 0.01},
        "flow_summary": {
            "top_flows": [
                {
                    "protocol": "udp",
                    "endpoint_a": "10.0.0.2:46485",
                    "endpoint_b": "157.240.146.35:3478",
                    "packets": 47_480,
                    "bytes": 43_000_000,
                    "directionality": "mixed",
                }
            ]
        },
    }
    summary = summarize_media_plane(report, pcap_path=pcap_path, tshark_path="tshark")
    assert summary["status"] == "ok"
    payload = summary["summary"]
    assert payload["classification"] == "relay_media_likely"
    assert payload["relay_media_likely"] is True
    assert payload["turn_allocate_request_count"] >= 1
    assert payload["turn_allocate_success_count"] >= 1
    assert payload["relay_endpoint_count"] >= 1
    assert payload["dominant_udp_flow"]["share_of_udp_bytes"] == 43_000_000 / 43_500_000


def test_media_plane_handles_report_without_udp_media() -> None:
    report = {
        "protocol_hierarchy_agg": {"bytes": {"ip": 1000, "tcp": 900}, "frames": {"ip": 10, "tcp": 9}},
        "protocol_ratios": {"udp_ratio": 0.0, "tcp_ratio": 0.9},
        "flow_summary": {"top_flows": []},
    }
    summary = summarize_media_plane(report)
    assert summary["status"] == "no_observations"
    assert summary["summary"]["classification"] == "not_observed"
    assert summary["summary"]["turn_allocate_success_count"] == 0
