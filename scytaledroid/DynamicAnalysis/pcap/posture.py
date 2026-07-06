"""Derived traffic-posture summaries for PCAP-backed dynamic runs.

These summaries are built from already-collected metadata:
- capture metrics
- direction summaries
- flow summaries
- burst summaries
- TLS/QUIC visibility summaries

No payload inspection is added here. The goal is to expose higher-signal,
comparable shape metrics so analysts and downstream DB/report consumers do not
have to manually reinterpret raw counters for every run.
"""

from __future__ import annotations

from typing import Any


def summarize_traffic_posture(
    *,
    metrics: dict[str, Any] | None,
    direction_summary: dict[str, Any] | None,
    flow_summary: dict[str, Any] | None,
    burst_summary: dict[str, Any] | None,
    visibility_summary: dict[str, Any] | None,
    startup_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    metrics = metrics if isinstance(metrics, dict) else {}
    direction_summary = direction_summary if isinstance(direction_summary, dict) else {}
    flow_summary = flow_summary if isinstance(flow_summary, dict) else {}
    burst_summary = burst_summary if isinstance(burst_summary, dict) else {}
    visibility_summary = visibility_summary if isinstance(visibility_summary, dict) else {}
    startup_summary = startup_summary if isinstance(startup_summary, dict) else {}

    packet_count = _safe_float(metrics.get("packet_count"))
    data_size_bytes = _safe_float(metrics.get("data_size_bytes"))
    duration_s = _safe_float(metrics.get("capture_duration_s"))

    outbound_packets = _safe_float(direction_summary.get("outbound_packets"))
    inbound_packets = _safe_float(direction_summary.get("inbound_packets"))
    unknown_packets = _safe_float(direction_summary.get("unknown_packets"))
    outbound_bytes = _safe_float(direction_summary.get("outbound_bytes"))
    inbound_bytes = _safe_float(direction_summary.get("inbound_bytes"))
    unknown_bytes = _safe_float(direction_summary.get("unknown_bytes"))

    total_direction_packets = _sum_known(outbound_packets, inbound_packets, unknown_packets)
    total_direction_bytes = _sum_known(outbound_bytes, inbound_bytes, unknown_bytes)

    confidence_counts = (
        direction_summary.get("confidence_counts")
        if isinstance(direction_summary.get("confidence_counts"), dict)
        else {}
    )
    confident_packets = _sum_known(
        _safe_float(confidence_counts.get("high")),
        _safe_float(confidence_counts.get("medium")),
    )

    active_second_count = _safe_float(burst_summary.get("active_second_count"))
    burst_count = _safe_float(burst_summary.get("burst_count"))

    tls_handshake_packets = _safe_float(visibility_summary.get("tls_handshake_packets"))
    startup_byte_share = _safe_float(startup_summary.get("startup_byte_share"))
    startup_packet_share = _safe_float(startup_summary.get("startup_packet_share"))
    post_start_median_bytes_per_min = _safe_float(startup_summary.get("post_start_median_bytes_per_min"))
    post_start_mean_bytes_per_min = _safe_float(startup_summary.get("post_start_mean_bytes_per_min"))
    startup_dominant = startup_summary.get("startup_dominant")

    top_flows = flow_summary.get("top_flows") if isinstance(flow_summary.get("top_flows"), list) else []
    top_flow = top_flows[0] if top_flows and isinstance(top_flows[0], dict) else {}
    top_flow_bytes = _safe_float(top_flow.get("bytes"))
    top_flow_packets = _safe_float(top_flow.get("packets"))

    return {
        "outbound_packet_ratio": _ratio(outbound_packets, total_direction_packets),
        "inbound_packet_ratio": _ratio(inbound_packets, total_direction_packets),
        "outbound_byte_ratio": _ratio(outbound_bytes, total_direction_bytes),
        "inbound_byte_ratio": _ratio(inbound_bytes, total_direction_bytes),
        "direction_confident_packet_ratio": _ratio(confident_packets, total_direction_packets),
        "active_second_ratio": _ratio(active_second_count, duration_s),
        "bursts_per_min": _per_minute(burst_count, duration_s),
        "median_packets_per_flow": _safe_float(flow_summary.get("median_packets_per_flow")),
        "median_bytes_per_flow": _safe_float(flow_summary.get("median_bytes_per_flow")),
        "top_flow_packet_share": _ratio(top_flow_packets, packet_count),
        "top_flow_byte_share": _ratio(top_flow_bytes, data_size_bytes),
        "tls_handshakes_per_min": _per_minute(tls_handshake_packets, duration_s),
        "startup_byte_share": startup_byte_share,
        "startup_packet_share": startup_packet_share,
        "post_start_median_bytes_per_min": post_start_median_bytes_per_min,
        "post_start_mean_bytes_per_min": post_start_mean_bytes_per_min,
        "startup_dominant": bool(startup_dominant) if startup_dominant is not None else None,
    }


def _safe_float(value: object) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _sum_known(*values: float | None) -> float | None:
    known = [value for value in values if value is not None]
    if not known:
        return None
    return float(sum(known))


def _ratio(numerator: float | None, denominator: float | None) -> float | None:
    if numerator is None or denominator is None:
        return None
    if numerator < 0 or denominator <= 0:
        return None
    ratio = float(numerator) / float(denominator)
    if ratio < 0:
        return 0.0
    if ratio > 1:
        return 1.0
    return ratio


def _per_minute(count: float | None, duration_s: float | None) -> float | None:
    if count is None or duration_s is None or duration_s <= 0:
        return None
    return float(count) / (float(duration_s) / 60.0)


__all__ = ["summarize_traffic_posture"]
