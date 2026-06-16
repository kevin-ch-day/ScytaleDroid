from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap import timeseries


class _FakeStdout:
    def __init__(self, lines: list[str]) -> None:
        self._lines = lines

    def __iter__(self):
        return iter(self._lines)

    def close(self) -> None:
        return None


class _FakeProc:
    def __init__(self, lines: list[str]) -> None:
        self.stdout = _FakeStdout(lines)

    def wait(self, timeout: float | None = None) -> int:
        return 0


def test_infer_direction_from_ports_labels_known_and_unknown_roles() -> None:
    assert timeseries.infer_direction_from_ports(src_port=52000, dst_port=443) == (
        "outbound",
        "high",
        "ephemeral_to_service",
    )
    assert timeseries.infer_direction_from_ports(src_port=443, dst_port=52000) == (
        "inbound",
        "high",
        "service_to_ephemeral",
    )
    assert timeseries.infer_direction_from_ports(src_port=62000, dst_port=62001) == (
        "unknown",
        "unknown",
        "ambiguous_port_roles",
    )


def test_scan_pcap_timeseries_includes_direction_flow_burst_and_visibility(monkeypatch, tmp_path: Path) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")

    lines = [
        # outbound tcp client hello
        "0.1\t100\t10.0.0.2\t31.13.70.1\t52000\t443\t\t\t7\t1\tgraph.facebook.com\th2",
        # inbound tcp server hello
        "0.2\t120\t31.13.70.1\t10.0.0.2\t443\t52000\t\t\t7\t2\t\t",
        # outbound udp dns
        "2.1\t80\t10.0.0.2\t8.8.8.8\t\t\t53000\t53\t\t\t\t",
        # unknown high-high udp
        "6.2\t60\t10.0.0.2\t52.1.1.1\t\t\t61000\t62000\t\t\t\t",
    ]

    monkeypatch.setattr(timeseries.subprocess, "Popen", lambda *args, **kwargs: _FakeProc(lines))
    stats = timeseries.scan_pcap_timeseries_and_destinations(pcap_path, tshark_path="tshark")

    assert stats["unique_dst_ip_count"] == 4
    assert stats["unique_dst_port_count"] == 4
    assert stats["direction_summary"]["outbound_packets"] == 2
    assert stats["direction_summary"]["inbound_packets"] == 1
    assert stats["direction_summary"]["unknown_packets"] == 1
    assert stats["flow_summary"]["flow_count"] >= 2
    assert stats["burst_summary"]["burst_count"] == 3
    assert stats["tls_quic_visibility"]["tls_handshake_packets"] == 2
    assert stats["tls_quic_visibility"]["tls_sni_unique_count"] == 1
    assert stats["tls_quic_visibility"]["tls_alpn_unique_count"] == 1
