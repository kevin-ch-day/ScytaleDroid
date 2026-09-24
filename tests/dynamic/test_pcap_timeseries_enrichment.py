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


def test_tls_name_visibility_does_not_claim_ech_from_missing_sni() -> None:
    visibility = timeseries.classify_tls_name_metadata_visibility(
        tls_handshake_packets=1,
        tls_client_hello_packets=1,
        tls_sni_unique_count=0,
        quic_candidate_packets=0,
    )

    assert visibility == {
        "tls_name_metadata_class": "client_hello_observed_without_sni",
        "tls_name_metadata_limited": True,
        "tls_name_metadata_basis": "decoded_client_hello_sni_absent",
        "ech_status": "not_determinable_from_passive_metadata",
    }


def test_tls_name_visibility_marks_udp_service_port_signal_as_heuristic() -> None:
    visibility = timeseries.classify_tls_name_metadata_visibility(
        tls_handshake_packets=0,
        tls_client_hello_packets=0,
        tls_sni_unique_count=0,
        quic_candidate_packets=12,
    )

    assert visibility["tls_name_metadata_class"] == "udp_service_port_without_decoded_tls_name"
    assert visibility["tls_name_metadata_basis"] == "udp_80_443_heuristic_only"
    assert visibility["tls_name_metadata_limited"] is True


def test_scan_pcap_timeseries_includes_direction_flow_burst_and_visibility(
    monkeypatch, tmp_path: Path
) -> None:
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
    assert stats["startup_profile"]["startup_total_bytes"] == 360
    assert stats["startup_profile"]["startup_total_packets"] == 4
    assert stats["startup_profile"]["startup_byte_share"] == 1.0
    assert stats["startup_profile"]["startup_dominant"] is True
    assert stats["startup_profile"]["post_start_total_bytes"] == 0
    assert stats["tls_quic_visibility"]["tls_handshake_packets"] == 2
    assert stats["tls_quic_visibility"]["tls_sni_unique_count"] == 1
    assert stats["tls_quic_visibility"]["tls_alpn_unique_count"] == 1
    assert stats["tls_quic_visibility"]["tls_name_metadata_class"] == "sni_observed"
    assert stats["tls_quic_visibility"]["tls_name_metadata_limited"] is False


def test_icmp_quoted_udp_is_not_an_additional_transport_flow():
    from scytaledroid.DynamicAnalysis.pcap.enrichment import flow_key, parse_packet_metadata_line

    row = "1\t150\t10.0.2.2,10.0.2.15\t10.0.2.15,224.0.0.251\t\t\t5353\t5353\t\t\t\t\teth:ip:icmp:ip:udp:mdns\t\t"
    packet = parse_packet_metadata_line(row)
    assert packet.length == 150
    assert packet.src_ip == "10.0.2.2" and packet.dst_ip == "10.0.2.15"
    assert packet.transport == "icmp" and packet.src_port is None
    assert flow_key(packet) is None


def test_ipv6_dns_has_real_addresses_but_icmpv6_quote_is_not_udp():
    from scytaledroid.DynamicAnalysis.pcap.enrichment import flow_key, parse_packet_metadata_line

    fields = [
        "1",
        "90",
        "",
        "",
        "",
        "",
        "53000",
        "53",
        "",
        "",
        "",
        "",
        "eth:ipv6:udp:dns",
        "2001:db8::1",
        "2001:db8::2",
    ]
    packet = parse_packet_metadata_line("\t".join(fields))
    assert packet.src_ip == "2001:db8::1" and packet.dst_ip == "2001:db8::2"
    assert packet.transport == "udp" and flow_key(packet) is not None
    fields[12] = "eth:ipv6:icmpv6:ipv6:udp:dns"
    fields[13] = "2001:db8::2,2001:db8::1"
    fields[14] = "2001:db8::1,2001:db8::2"
    packet = parse_packet_metadata_line("\t".join(fields))
    assert packet.transport == "icmpv6" and flow_key(packet) is None
    assert packet.src_ip == "2001:db8::2"


def test_ip_tunnel_is_not_assigned_mixed_layer_transport_endpoints():
    from scytaledroid.DynamicAnalysis.pcap.enrichment import flow_key, parse_packet_metadata_line

    fields = [
        "1",
        "90",
        "192.0.2.1,10.0.0.1",
        "192.0.2.2,10.0.0.2",
        "52000",
        "443",
        "",
        "",
        "1",
        "1",
        "example.test",
        "h2",
        "eth:ip:ip:tcp:tls",
    ]
    packet = parse_packet_metadata_line("\t".join(fields))
    assert packet.transport == "unknown" and flow_key(packet) is None
    assert packet.tls_sni is None and packet.tls_handshake_type is None
