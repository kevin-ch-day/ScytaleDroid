"""PCAP time-series scanning helpers (streaming, metadata-only).

These helpers are shared across:
- analysis/pcap_features.json enrichment (per-run summaries)
- derived DB indexing from evidence packs (optional accelerator)

Contract/safety:
- Uses tshark field extraction only; no payload inspection.
- Deterministic computations (discrete percentiles over 0-filled seconds; includes 0-activity seconds).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .enrichment import (
    PacketMetadata,
    compute_burst_summary,
    endpoint_label,
    flow_key,
    infer_direction_from_ports,
    packet_metadata_command,
    parse_packet_metadata_line,
    percentile,
    summarize_flows,
)


def classify_tls_name_metadata_visibility(
    *,
    tls_handshake_packets: int,
    tls_client_hello_packets: int,
    tls_sni_unique_count: int,
    quic_candidate_packets: int,
) -> dict[str, Any]:
    """Classify passive TLS name metadata without inferring encrypted payload semantics."""
    if tls_sni_unique_count > 0:
        visibility_class = "sni_observed"
        basis = "decoded_sni"
        limited = False
    elif tls_client_hello_packets > 0:
        visibility_class = "client_hello_observed_without_sni"
        basis = "decoded_client_hello_sni_absent"
        limited = True
    elif tls_handshake_packets > 0:
        visibility_class = "tls_handshake_observed_without_client_hello_or_sni"
        basis = "partial_or_non_client_tls_handshake_visibility"
        limited = True
    elif quic_candidate_packets > 0:
        visibility_class = "udp_service_port_without_decoded_tls_name"
        basis = "udp_80_443_heuristic_only"
        limited = True
    else:
        visibility_class = "no_tls_quic_name_signal"
        basis = "no_decoded_tls_or_udp_service_port_signal"
        limited = False
    return {
        "tls_name_metadata_class": visibility_class,
        "tls_name_metadata_limited": limited,
        "tls_name_metadata_basis": basis,
        "ech_status": "not_determinable_from_passive_metadata",
    }


def scan_pcap_timeseries_and_destinations(pcap_path: Path, *, tshark_path: str | None = None) -> dict[str, Any]:
    """Scan PCAP with tshark fields output (streaming) and compute summary stats.

    Returns:
      - bytes_per_second_{p50,p95,max}
      - packets_per_second_{p50,p95,max}
      - burstiness_{bytes,packets}_p95_over_p50
      - unique_dst_ip_count
      - unique_dst_port_count
      - direction_summary
      - flow_summary
      - burst_summary
      - startup_profile
      - tls_quic_visibility
    """
    tp = tshark_path or shutil.which("tshark")
    if not tp:
        raise RuntimeError("tshark_missing")
    if not pcap_path.exists():
        raise RuntimeError("pcap_missing")

    cmd = packet_metadata_command(tp, pcap_path)

    bytes_by_s: dict[int, int] = {}
    pkts_by_s: dict[int, int] = {}
    uniq_ip: set[str] = set()
    uniq_port: set[int] = set()
    max_sec = 0
    flow_stats: dict[tuple[str, str], dict[str, Any]] = {}
    direction_packets = {"outbound": 0, "inbound": 0, "unknown": 0}
    direction_bytes = {"outbound": 0, "inbound": 0, "unknown": 0}
    direction_methods = {"high": 0, "medium": 0, "unknown": 0}
    tls_handshake_total = 0
    tls_client_hello_count = 0
    tls_server_hello_count = 0
    tls_sni_values: set[str] = set()
    tls_alpn_values: set[str] = set()
    quic_candidate_packets = 0

    # tshark can be verbose on stderr for malformed captures; discard stderr in
    # this streaming path to avoid deadlocks. We only need deterministic stats.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            packet = parse_packet_metadata_line(line)
            if packet is None:
                continue
            sec = int(packet.t) if packet.t >= 0 else 0
            max_sec = max(max_sec, sec)
            bytes_by_s[sec] = bytes_by_s.get(sec, 0) + max(packet.length, 0)
            pkts_by_s[sec] = pkts_by_s.get(sec, 0) + 1

            if packet.dst_ip:
                uniq_ip.add(packet.dst_ip)
            if packet.dst_port is not None:
                uniq_port.add(packet.dst_port)

            direction_packets[packet.direction] = direction_packets.get(packet.direction, 0) + 1
            direction_bytes[packet.direction] = direction_bytes.get(packet.direction, 0) + int(packet.length)
            direction_methods[packet.direction_confidence] = direction_methods.get(packet.direction_confidence, 0) + 1

            if packet.transport == "udp" and (
                packet.src_port == 443 or packet.dst_port == 443 or packet.src_port == 80 or packet.dst_port == 80
            ):
                quic_candidate_packets += 1

            if packet.tls_handshake_type:
                tls_handshake_total += 1
                if packet.tls_handshake_type == "1":
                    tls_client_hello_count += 1
                elif packet.tls_handshake_type == "2":
                    tls_server_hello_count += 1
            if packet.tls_sni:
                tls_sni_values.add(packet.tls_sni)
            if packet.tls_alpn:
                tls_alpn_values.add(packet.tls_alpn)

            key = flow_key(packet)
            if key is None:
                continue
            entry = flow_stats.setdefault(
                key,
                {
                    "protocol": packet.transport,
                    "packets": 0,
                    "bytes": 0,
                    "endpoint_a": endpoint_label(packet.src_ip, packet.src_port),
                    "endpoint_b": endpoint_label(packet.dst_ip, packet.dst_port),
                    "outbound_packets": 0,
                    "inbound_packets": 0,
                    "unknown_packets": 0,
                },
            )
            entry["packets"] += 1
            entry["bytes"] += int(packet.length)
            entry[f"{packet.direction}_packets"] += 1
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
    timeout_s = _resolve_tshark_timeout_s()
    try:
        rc = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired as err:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            rc = proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                rc = proc.wait(timeout=5)
            except Exception:
                rc = -1
        raise RuntimeError("tshark_timeout") from err
    if rc != 0:
        raise RuntimeError("tshark_failed")

    # Include seconds with 0 activity so percentiles reflect burstiness.
    bytes_series = [float(bytes_by_s.get(i, 0)) for i in range(max_sec + 1)]
    pkts_series = [float(pkts_by_s.get(i, 0)) for i in range(max_sec + 1)]
    bytes_sorted = sorted(bytes_series)
    pkts_sorted = sorted(pkts_series)

    b50 = percentile(bytes_sorted, 50)
    b95 = percentile(bytes_sorted, 95)
    p50 = percentile(pkts_sorted, 50)
    p95 = percentile(pkts_sorted, 95)
    bmax = float(bytes_sorted[-1]) if bytes_sorted else None
    pmax = float(pkts_sorted[-1]) if pkts_sorted else None

    burst_b = (float(b95) / float(b50)) if b50 and b95 is not None and b50 > 0 else None
    burst_p = (float(p95) / float(p50)) if p50 and p95 is not None and p50 > 0 else None
    burst_summary = compute_burst_summary(bytes_by_s, pkts_by_s)
    flow_summary = summarize_flows(flow_stats)
    startup_profile = _startup_profile_summary(bytes_by_s, pkts_by_s, duration_s=float(max_sec + 1))

    name_visibility = classify_tls_name_metadata_visibility(
        tls_handshake_packets=tls_handshake_total,
        tls_client_hello_packets=tls_client_hello_count,
        tls_sni_unique_count=len(tls_sni_values),
        quic_candidate_packets=quic_candidate_packets,
    )

    return {
        "bytes_per_second_p50": b50,
        "bytes_per_second_p95": b95,
        "bytes_per_second_max": bmax,
        "packets_per_second_p50": p50,
        "packets_per_second_p95": p95,
        "packets_per_second_max": pmax,
        "burstiness_bytes_p95_over_p50": burst_b,
        "burstiness_packets_p95_over_p50": burst_p,
        "unique_dst_ip_count": len(uniq_ip) if uniq_ip else 0,
        "unique_dst_port_count": len(uniq_port) if uniq_port else 0,
        "direction_summary": {
            "method": "service_port_heuristic",
            "outbound_packets": int(direction_packets["outbound"]),
            "inbound_packets": int(direction_packets["inbound"]),
            "unknown_packets": int(direction_packets["unknown"]),
            "outbound_bytes": int(direction_bytes["outbound"]),
            "inbound_bytes": int(direction_bytes["inbound"]),
            "unknown_bytes": int(direction_bytes["unknown"]),
            "confidence_counts": {
                "high": int(direction_methods["high"]),
                "medium": int(direction_methods["medium"]),
                "unknown": int(direction_methods["unknown"]),
            },
        },
        "flow_summary": flow_summary,
        "burst_summary": burst_summary,
        "startup_profile": startup_profile,
        "tls_quic_visibility": {
            "tls_handshake_packets": int(tls_handshake_total),
            "tls_client_hello_packets": int(tls_client_hello_count),
            "tls_server_hello_packets": int(tls_server_hello_count),
            "tls_sni_unique_count": int(len(tls_sni_values)),
            "tls_alpn_unique_count": int(len(tls_alpn_values)),
            "quic_candidate_packets": int(quic_candidate_packets),
            "tls_visible": bool(tls_handshake_total or tls_sni_values or tls_alpn_values),
            "quic_visibility_basis": "udp_service_port_heuristic",
            **name_visibility,
        },
        "window_metrics": {
            "180s": _window_metric_summary(bytes_by_s, pkts_by_s, window_s=180),
            "240s": _window_metric_summary(bytes_by_s, pkts_by_s, window_s=240),
        },
    }


def _resolve_tshark_timeout_s() -> float:
    raw = os.getenv("SCYTALEDROID_TSHARK_TIMEOUT_S", "120").strip()
    try:
        return max(5.0, float(raw))
    except ValueError:
        return 120.0


def _window_metric_summary(
    bytes_by_s: dict[int, int],
    pkts_by_s: dict[int, int],
    *,
    window_s: int,
) -> dict[str, Any]:
    byte_series = [float(bytes_by_s.get(i, 0)) for i in range(window_s)]
    pkt_series = [float(pkts_by_s.get(i, 0)) for i in range(window_s)]
    byte_sorted = sorted(byte_series)
    pkt_sorted = sorted(pkt_series)
    total_bytes = int(sum(bytes_by_s.get(i, 0) for i in range(window_s)))
    total_packets = int(sum(pkts_by_s.get(i, 0) for i in range(window_s)))
    active_second_count = sum(
        1
        for i in range(window_s)
        if bytes_by_s.get(i, 0) > 0 or pkts_by_s.get(i, 0) > 0
    )
    return {
        "window_s": int(window_s),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "avg_bytes_per_sec": float(total_bytes) / float(window_s),
        "avg_packets_per_sec": float(total_packets) / float(window_s),
        "bytes_per_second_p95": percentile(byte_sorted, 95),
        "packets_per_second_p95": percentile(pkt_sorted, 95),
        "active_second_count": int(active_second_count),
        "active_second_ratio": float(active_second_count) / float(window_s),
    }


def _startup_profile_summary(
    bytes_by_s: dict[int, int],
    pkts_by_s: dict[int, int],
    *,
    duration_s: float,
    startup_window_s: int = 60,
) -> dict[str, Any]:
    if duration_s <= 0:
        return {
            "window_s": int(startup_window_s),
            "startup_total_bytes": 0,
            "startup_total_packets": 0,
            "startup_byte_share": None,
            "startup_packet_share": None,
            "post_start_total_bytes": 0,
            "post_start_total_packets": 0,
            "post_start_minutes": 0,
            "post_start_median_bytes_per_min": None,
            "post_start_mean_bytes_per_min": None,
            "post_start_median_packets_per_min": None,
            "post_start_mean_packets_per_min": None,
            "startup_dominant": False,
        }

    effective_window = max(1, int(startup_window_s))
    startup_total_bytes = int(sum(bytes_by_s.get(i, 0) for i in range(effective_window)))
    startup_total_packets = int(sum(pkts_by_s.get(i, 0) for i in range(effective_window)))
    total_bytes = int(sum(bytes_by_s.values()))
    total_packets = int(sum(pkts_by_s.values()))

    post_start_seconds = max(0, int(duration_s) - effective_window)
    post_start_total_bytes = int(sum(v for sec, v in bytes_by_s.items() if sec >= effective_window))
    post_start_total_packets = int(sum(v for sec, v in pkts_by_s.items() if sec >= effective_window))

    minute_bytes: list[int] = []
    minute_packets: list[int] = []
    if post_start_seconds > 0:
        max_sec = max(max(bytes_by_s.keys(), default=0), max(pkts_by_s.keys(), default=0))
        start = effective_window
        while start <= max_sec:
            end = start + 60
            minute_bytes.append(int(sum(v for sec, v in bytes_by_s.items() if start <= sec < end)))
            minute_packets.append(int(sum(v for sec, v in pkts_by_s.items() if start <= sec < end)))
            start = end

    return {
        "window_s": int(effective_window),
        "startup_total_bytes": startup_total_bytes,
        "startup_total_packets": startup_total_packets,
        "startup_byte_share": float(startup_total_bytes) / float(total_bytes) if total_bytes > 0 else None,
        "startup_packet_share": float(startup_total_packets) / float(total_packets) if total_packets > 0 else None,
        "startup_avg_bytes_per_sec": float(startup_total_bytes) / float(effective_window),
        "startup_avg_packets_per_sec": float(startup_total_packets) / float(effective_window),
        "post_start_total_bytes": post_start_total_bytes,
        "post_start_total_packets": post_start_total_packets,
        "post_start_minutes": len(minute_bytes),
        "post_start_median_bytes_per_min": percentile(sorted(float(v) for v in minute_bytes), 50) if minute_bytes else None,
        "post_start_mean_bytes_per_min": (float(sum(minute_bytes)) / float(len(minute_bytes))) if minute_bytes else None,
        "post_start_median_packets_per_min": percentile(sorted(float(v) for v in minute_packets), 50) if minute_packets else None,
        "post_start_mean_packets_per_min": (float(sum(minute_packets)) / float(len(minute_packets))) if minute_packets else None,
        "startup_dominant": bool(total_bytes > 0 and (float(startup_total_bytes) / float(total_bytes)) >= 0.8),
    }
__all__ = [
    "PacketMetadata",
    "classify_tls_name_metadata_visibility",
    "infer_direction_from_ports",
    "percentile",
    "scan_pcap_timeseries_and_destinations",
]
