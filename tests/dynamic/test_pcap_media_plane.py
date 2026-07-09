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
    assert payload["rtc_relay_peer_count"] == 0
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


def test_media_plane_derives_sustained_rtc_sessions(monkeypatch, tmp_path: Path) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")

    def _fake_run(cmd):
        if "-e" in cmd and "stun.type" in cmd:
            return {
                "stdout": "\n".join(
                    [
                        "0x0003\t0x0003\t0x0000\t57.144.175.132\t3478",
                        "0x0103\t0x0003\t0x0010\t76.156.25.138\t43564",
                    ]
                ),
                "stderr": "",
                "error": None,
            }
        return {
            "stdout": "\n".join(
                [
                    "40.000\t192.168.0.23\t48869\t57.144.175.132\t3478\t6000\tip:udp:stun",
                    "65.000\t57.144.175.132\t3478\t192.168.0.23\t48869\t5000\tip:udp:dtls",
                    "97.416\t192.168.0.23\t48181\t57.144.175.132\t3478\t120000\tip:udp:rtp",
                    "180.000\t57.144.175.132\t3478\t192.168.0.23\t48181\t118000\tip:udp:srtcp",
                    "370.559\t192.168.0.23\t48181\t57.144.175.132\t3478\t122000\tip:udp:rtp",
                    "378.497\t192.168.0.23\t39020\t57.144.175.132\t3478\t118000\tip:udp:rtp",
                    "420.000\t57.144.175.132\t3478\t192.168.0.23\t39020\t116000\tip:udp:srtcp",
                    "542.083\t192.168.0.23\t39020\t57.144.175.132\t3478\t119000\tip:udp:rtp",
                    "410.000\t192.168.0.23\t39020\t157.240.22.10\t443\t1350\tip:udp:quic",
                ]
            ),
            "stderr": "",
            "error": None,
        }

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.media_plane._run_command",
        _fake_run,
    )
    report = {
        "protocol_hierarchy_agg": {
            "bytes": {"ip": 4_400_000, "udp": 4_200_000, "quic": 400_000},
            "frames": {"ip": 17_000, "udp": 16_500, "stun": 480, "quic": 65},
        },
        "protocol_ratios": {"udp_ratio": 0.95, "tcp_ratio": 0.05, "tls_ratio": 0.0, "quic_ratio": 0.24},
        "flow_summary": {
            "top_flows": [
                {
                    "protocol": "udp",
                    "endpoint_a": "192.168.0.23:39020",
                    "endpoint_b": "57.144.175.132:3478",
                    "packets": 4700,
                    "bytes": 621_345,
                    "directionality": "mixed",
                }
            ]
        },
    }

    summary = summarize_media_plane(report, pcap_path=pcap_path, tshark_path="tshark")
    payload = summary["summary"]
    assert payload["rtc_flow_candidate_count"] == 3
    assert payload["rtc_sustained_session_count"] == 2
    assert payload["rtc_call_observed"] is True
    assert payload["rtc_multi_session_observed"] is True
    assert payload["rtc_total_bytes"] == 724_000
    assert payload["rtc_total_packets"] == 8
    assert payload["rtc_stun_packet_count"] == 1
    assert payload["rtc_dtls_packet_count"] == 1
    assert payload["rtc_rtp_packet_count"] == 4
    assert payload["rtc_srtcp_packet_count"] == 2
    assert payload["rtc_quic_packet_count"] == 0
    assert payload["rtc_max_session_bytes"] == 360_000
    assert payload["rtc_max_session_duration_s"] == 273.143
    assert payload["rtc_relay_peer_count"] == 1
    assert payload["rtc_relay_peers"] == ["57.144.175.132:3478"]
    assert payload["rtc_sessions"][0]["sustained"] is True
    assert payload["rtc_sessions"][0]["bytes"] >= 3_000
    assert "multi_phase_rtc_observed" in payload["reason_codes"]


def test_media_plane_detects_multi_phase_opaque_udp_media(monkeypatch, tmp_path: Path) -> None:
    pcap_path = tmp_path / "signal-video.pcap"
    pcap_path.write_bytes(b"pcap")

    def _fake_run(cmd):
        if "-e" in cmd and "stun.type" in cmd:
            return {
                "stdout": "\n".join(
                    [
                        "0x0003\t0x0003\t0x0000\t141.101.90.1\t3478",
                        "0x0103\t0x0003\t0x0010\t10.215.173.1\t48679",
                    ]
                ),
                "stderr": "",
                "error": None,
            }
        rows = []
        for idx in range(600):
            ts = 43.944 + (200.274 * idx / 599)
            src, dst = (
                ("10.215.173.1\t48679", "192.168.0.13\t57159")
                if idx % 2 == 0
                else ("192.168.0.13\t57159", "10.215.173.1\t48679")
            )
            rows.append(f"{ts:.3f}\t{src}\t{dst}\t10000\tip:udp:data")
        for idx in range(600):
            ts = 295.785 + (211.805 * idx / 599)
            src, dst = (
                ("10.215.173.1\t41313", "192.168.0.13\t63166")
                if idx % 2 == 0
                else ("192.168.0.13\t63166", "10.215.173.1\t41313")
            )
            rows.append(f"{ts:.3f}\t{src}\t{dst}\t10000\tip:udp:data")
        rows.append("295.284\t10.215.173.1\t41313\t141.101.90.1\t3478\t120\tip:udp:stun")
        stdout = "\n".join(rows)
        return {"stdout": stdout, "stderr": "", "error": None}

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.media_plane._run_command",
        _fake_run,
    )
    report = {
        "protocol_hierarchy_agg": {
            "bytes": {"ip": 200_000_000, "udp": 190_000_000},
            "frames": {"ip": 200_000, "udp": 198_000, "stun": 1000},
        },
        "protocol_ratios": {"udp_ratio": 0.99, "tcp_ratio": 0.01},
        "flow_summary": {
            "top_flows": [
                {
                    "protocol": "udp",
                    "endpoint_a": "10.215.173.1:48679",
                    "endpoint_b": "192.168.0.13:57159",
                    "packets": 96_346,
                    "bytes": 92_210_145,
                    "directionality": "unknown",
                }
            ]
        },
    }

    summary = summarize_media_plane(report, pcap_path=pcap_path, tshark_path="tshark")
    payload = summary["summary"]

    assert payload["classification"] == "multi_phase_opaque_udp_media_observed"
    assert payload["relay_media_likely"] is True
    assert payload["udp_media_session_count"] == 2
    assert payload["udp_media_multi_session_observed"] is True
    assert payload["udp_media_total_bytes"] == 12_000_000
    assert payload["udp_media_sessions"][0]["duration_s"] == 200.274
    assert payload["udp_media_sessions"][1]["duration_s"] == 211.805
    assert "multi_phase_opaque_udp_media_observed" in payload["reason_codes"]
