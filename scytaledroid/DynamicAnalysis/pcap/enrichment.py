"""Shared PCAP enrichment helpers.

These helpers keep heuristic, append-only enrichment logic separate from the
streaming tshark scan/orchestration layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

_COMMON_SERVICE_PORTS = {
    53,
    80,
    123,
    443,
    853,
    3478,
    3479,
    5222,
    5223,
    5228,
    8080,
    8443,
}
_EPHEMERAL_PORT_FLOOR = 49152


def percentile(sorted_values: list[float], p: float) -> float | None:
    if not sorted_values:
        return None
    if p <= 0:
        return float(sorted_values[0])
    if p >= 100:
        return float(sorted_values[-1])
    k = int((p / 100.0) * (len(sorted_values) - 1))
    k = max(0, min(k, len(sorted_values) - 1))
    return float(sorted_values[k])


@dataclass(frozen=True)
class PacketMetadata:
    t: float
    length: int
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    transport: str
    tcp_stream: str | None
    tls_handshake_type: str | None
    tls_sni: str | None
    tls_alpn: str | None
    direction: str
    direction_confidence: str
    direction_reason: str


def packet_metadata_command(tshark_path: str, pcap_path: Path) -> list[str]:
    return [
        tshark_path,
        "-n",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.time_relative",
        "-e",
        "frame.len",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "tcp.stream",
        "-e",
        "tls.handshake.type",
        "-e",
        "tls.handshake.extensions_server_name",
        "-e",
        "tls.handshake.extensions_alpn_str",
    ]


def parse_packet_metadata_line(line: str) -> PacketMetadata | None:
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2:
        return None
    t_s = parts[0].strip()
    l_s = parts[1].strip()
    if not t_s or not l_s:
        return None
    try:
        t = float(t_s)
        length = int(float(l_s))
    except Exception:
        return None
    src_ip = clean_text(parts[2] if len(parts) >= 3 else "")
    dst_ip = clean_text(parts[3] if len(parts) >= 4 else "")
    tcp_src = safe_port(parts[4] if len(parts) >= 5 else "")
    tcp_dst = safe_port(parts[5] if len(parts) >= 6 else "")
    udp_src = safe_port(parts[6] if len(parts) >= 7 else "")
    udp_dst = safe_port(parts[7] if len(parts) >= 8 else "")
    tcp_stream = clean_text(parts[8] if len(parts) >= 9 else "")
    tls_type = clean_text(parts[9] if len(parts) >= 10 else "")
    tls_sni = clean_text(parts[10] if len(parts) >= 11 else "")
    tls_alpn = clean_text(parts[11] if len(parts) >= 12 else "")

    transport = "unknown"
    src_port = None
    dst_port = None
    if tcp_src is not None or tcp_dst is not None:
        transport = "tcp"
        src_port = tcp_src
        dst_port = tcp_dst
    elif udp_src is not None or udp_dst is not None:
        transport = "udp"
        src_port = udp_src
        dst_port = udp_dst

    direction, confidence, reason = infer_direction_from_ports(
        src_port=src_port,
        dst_port=dst_port,
        tls_handshake_type=tls_type,
    )
    return PacketMetadata(
        t=t,
        length=max(length, 0),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport=transport,
        tcp_stream=tcp_stream,
        tls_handshake_type=tls_type,
        tls_sni=tls_sni,
        tls_alpn=tls_alpn,
        direction=direction,
        direction_confidence=confidence,
        direction_reason=reason,
    )


def infer_direction_from_ports(
    *,
    src_port: int | None,
    dst_port: int | None,
    tls_handshake_type: str | None = None,
) -> tuple[str, str, str]:
    if src_port is None and dst_port is None:
        return ("unknown", "unknown", "missing_ports")

    src_service = is_service_port(src_port)
    dst_service = is_service_port(dst_port)
    src_ephemeral = is_ephemeral_port(src_port)
    dst_ephemeral = is_ephemeral_port(dst_port)

    if src_ephemeral and dst_service and src_port != dst_port:
        return ("outbound", "high", "ephemeral_to_service")
    if dst_ephemeral and src_service and src_port != dst_port:
        return ("inbound", "high", "service_to_ephemeral")
    if tls_handshake_type == "1" and dst_service:
        return ("outbound", "medium", "tls_client_hello_to_service")
    if tls_handshake_type == "2" and src_service:
        return ("inbound", "medium", "tls_server_hello_from_service")
    if dst_service and not src_service and src_port != dst_port:
        return ("outbound", "medium", "dst_service_port")
    if src_service and not dst_service and src_port != dst_port:
        return ("inbound", "medium", "src_service_port")
    return ("unknown", "unknown", "ambiguous_port_roles")


def is_service_port(port: int | None) -> bool:
    if port is None:
        return False
    return port in _COMMON_SERVICE_PORTS or 0 < port < 1024


def is_ephemeral_port(port: int | None) -> bool:
    if port is None:
        return False
    return port >= _EPHEMERAL_PORT_FLOOR


def safe_port(raw: str) -> int | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        value = int(text)
    except Exception:
        return None
    if 0 <= value <= 65535:
        return value
    return None


def clean_text(raw: str) -> str | None:
    text = str(raw or "").strip()
    return text or None


def endpoint_label(ip: str | None, port: int | None) -> str:
    if ip and port is not None:
        return f"{ip}:{port}"
    if ip:
        return ip
    if port is not None:
        return f":{port}"
    return "unknown"


def flow_key(packet: PacketMetadata) -> tuple[str, str] | None:
    if packet.transport == "tcp" and packet.tcp_stream:
        return ("tcp", packet.tcp_stream)
    if packet.src_ip and packet.dst_ip and packet.src_port is not None and packet.dst_port is not None:
        a = f"{packet.src_ip}:{packet.src_port}"
        b = f"{packet.dst_ip}:{packet.dst_port}"
        return (packet.transport, "|".join(sorted((a, b))))
    return None


def summarize_flows(flow_stats: dict[tuple[str, str], dict[str, Any]]) -> dict[str, Any]:
    if not flow_stats:
        return {
            "flow_count": 0,
            "tcp_stream_count": 0,
            "udp_flow_count": 0,
            "median_packets_per_flow": None,
            "median_bytes_per_flow": None,
            "top_flows": [],
        }
    entries = list(flow_stats.values())
    packets = sorted(float(entry["packets"]) for entry in entries)
    bytes_ = sorted(float(entry["bytes"]) for entry in entries)
    top = sorted(entries, key=lambda item: (int(item["bytes"]), int(item["packets"])), reverse=True)[:5]
    top_rows: list[dict[str, Any]] = []
    for item in top:
        directionality = "unknown"
        if item["outbound_packets"] and item["inbound_packets"]:
            directionality = "mixed"
        elif item["outbound_packets"]:
            directionality = "outbound_only"
        elif item["inbound_packets"]:
            directionality = "inbound_only"
        top_rows.append(
            {
                "protocol": item["protocol"],
                "endpoint_a": item["endpoint_a"],
                "endpoint_b": item["endpoint_b"],
                "packets": int(item["packets"]),
                "bytes": int(item["bytes"]),
                "directionality": directionality,
            }
        )
    return {
        "flow_count": len(entries),
        "tcp_stream_count": sum(1 for key in flow_stats if key[0] == "tcp"),
        "udp_flow_count": sum(1 for key in flow_stats if key[0] == "udp"),
        "median_packets_per_flow": percentile(packets, 50),
        "median_bytes_per_flow": percentile(bytes_, 50),
        "top_flows": top_rows,
    }


def compute_burst_summary(bytes_by_s: dict[int, int], pkts_by_s: dict[int, int]) -> dict[str, Any]:
    active_seconds = sorted(sec for sec, value in bytes_by_s.items() if value > 0 or pkts_by_s.get(sec, 0) > 0)
    if not active_seconds:
        return {
            "active_second_count": 0,
            "burst_count": 0,
            "median_burst_duration_s": None,
            "max_burst_duration_s": None,
            "median_interburst_gap_s": None,
        }
    bursts: list[int] = []
    gaps: list[int] = []
    start = active_seconds[0]
    prev = active_seconds[0]
    for sec in active_seconds[1:]:
        if sec == prev + 1:
            prev = sec
            continue
        bursts.append((prev - start) + 1)
        gaps.append(sec - prev - 1)
        start = sec
        prev = sec
    bursts.append((prev - start) + 1)
    burst_values = sorted(float(value) for value in bursts)
    gap_values = sorted(float(value) for value in gaps)
    return {
        "active_second_count": len(active_seconds),
        "burst_count": len(bursts),
        "median_burst_duration_s": percentile(burst_values, 50),
        "max_burst_duration_s": float(max(bursts)) if bursts else None,
        "median_interburst_gap_s": percentile(gap_values, 50),
    }


__all__ = [
    "PacketMetadata",
    "clean_text",
    "compute_burst_summary",
    "endpoint_label",
    "flow_key",
    "infer_direction_from_ports",
    "packet_metadata_command",
    "parse_packet_metadata_line",
    "percentile",
    "safe_port",
    "summarize_flows",
]
