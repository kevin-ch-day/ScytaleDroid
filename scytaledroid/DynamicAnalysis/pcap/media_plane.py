"""PCAP media-plane understanding helpers.

This module stays payload-free and focuses on relay/call behavior that can be
inferred from protocol mix, STUN/TURN control messages, and dominant UDP flow
structure.
"""

from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path
from typing import Any


def summarize_media_plane(
    report: dict[str, Any],
    *,
    pcap_path: Path | None = None,
    tshark_path: str | None = None,
) -> dict[str, Any]:
    proto_bytes = _proto_bucket(report, "bytes")
    proto_frames = _proto_bucket(report, "frames")
    udp_bytes = _safe_int(proto_bytes.get("udp")) or 0
    udp_frames = _safe_int(proto_frames.get("udp")) or 0
    stun_frames = _safe_int(proto_frames.get("stun")) or 0
    quic_frames = _safe_int(proto_frames.get("quic")) or 0
    ratios = report.get("protocol_ratios") if isinstance(report.get("protocol_ratios"), dict) else {}
    udp_ratio = _safe_float((ratios or {}).get("udp_ratio"))
    flow_summary = report.get("flow_summary") if isinstance(report.get("flow_summary"), dict) else {}
    top_flows = flow_summary.get("top_flows") if isinstance(flow_summary.get("top_flows"), list) else []
    dominant_udp_flow = _select_dominant_udp_flow(top_flows, udp_bytes=udp_bytes)
    stun_turn = _summarize_stun_turn(pcap_path=pcap_path, tshark_path=tshark_path)
    rtc_sessions = _summarize_rtc_sessions(pcap_path=pcap_path, tshark_path=tshark_path)

    relay_media_likely = bool(
        stun_turn["turn_allocate_success_count"] > 0
        and dominant_udp_flow.get("share_of_udp_bytes") is not None
        and float(dominant_udp_flow["share_of_udp_bytes"]) >= 0.5
        and (udp_ratio or 0.0) >= 0.7
    )
    nat_traversal_observed = bool(
        stun_frames > 0
        or stun_turn["turn_allocate_request_count"] > 0
        or stun_turn["turn_allocate_success_count"] > 0
    )
    classification = "not_observed"
    reason_codes: list[str] = []
    if nat_traversal_observed:
        classification = "nat_traversal_observed"
        reason_codes.append("stun_turn_control_observed")
    if relay_media_likely:
        classification = "relay_media_likely"
        reason_codes.append("relay_media_pattern")
    elif dominant_udp_flow.get("share_of_udp_bytes") is not None and float(dominant_udp_flow["share_of_udp_bytes"]) >= 0.5:
        classification = "udp_media_candidate"
        reason_codes.append("dominant_udp_flow")
    if stun_turn["turn_allocate_success_count"] > 0:
        reason_codes.append("turn_allocate_success")
    if stun_turn["turn_allocate_request_count"] > 0:
        reason_codes.append("turn_allocate_request")
    if stun_frames > 0:
        reason_codes.append("stun_frames_present")
    if quic_frames > 0:
        reason_codes.append("quic_side_traffic_present")
    if rtc_sessions["rtc_flow_candidate_count"] > 0:
        reason_codes.append("rtc_flow_candidates_observed")
        if classification == "not_observed":
            classification = "rtc_session_candidate"
    if rtc_sessions["rtc_sustained_session_count"] > 0:
        reason_codes.append("sustained_rtc_session_observed")
        if rtc_sessions["rtc_sustained_session_count"] == 1 and classification != "relay_media_likely":
            classification = "rtc_media_session_observed"
    if rtc_sessions["rtc_sustained_session_count"] > 1:
        reason_codes.append("multi_phase_rtc_observed")
        classification = "multi_session_rtc_observed"

    summary = {
        "classification": classification,
        "relay_media_likely": relay_media_likely,
        "nat_traversal_observed": nat_traversal_observed,
        "udp_ratio": udp_ratio,
        "udp_bytes": udp_bytes,
        "udp_frames": udp_frames,
        "stun_frame_count": stun_frames,
        "stun_frame_share_of_udp": _bounded_ratio(stun_frames, udp_frames),
        "quic_frame_count": quic_frames,
        "turn_allocate_request_count": stun_turn["turn_allocate_request_count"],
        "turn_allocate_success_count": stun_turn["turn_allocate_success_count"],
        "relay_endpoint_count": len(stun_turn["relay_endpoints"]),
        "relay_endpoints": stun_turn["relay_endpoints"],
        "mapped_address_count": len(stun_turn["mapped_addresses"]),
        "mapped_addresses": stun_turn["mapped_addresses"],
        "dominant_udp_flow": dominant_udp_flow,
        "rtc_flow_candidate_count": rtc_sessions["rtc_flow_candidate_count"],
        "rtc_sustained_session_count": rtc_sessions["rtc_sustained_session_count"],
        "rtc_call_observed": bool(rtc_sessions["rtc_sustained_session_count"] > 0),
        "rtc_multi_session_observed": bool(rtc_sessions["rtc_sustained_session_count"] > 1),
        "rtc_total_bytes": rtc_sessions["rtc_total_bytes"],
        "rtc_total_packets": rtc_sessions["rtc_total_packets"],
        "rtc_stun_packet_count": rtc_sessions["rtc_stun_packet_count"],
        "rtc_dtls_packet_count": rtc_sessions["rtc_dtls_packet_count"],
        "rtc_rtp_packet_count": rtc_sessions["rtc_rtp_packet_count"],
        "rtc_srtcp_packet_count": rtc_sessions["rtc_srtcp_packet_count"],
        "rtc_quic_packet_count": rtc_sessions["rtc_quic_packet_count"],
        "rtc_max_session_bytes": rtc_sessions["rtc_max_session_bytes"],
        "rtc_max_session_duration_s": rtc_sessions["rtc_max_session_duration_s"],
        "rtc_relay_peer_count": rtc_sessions["rtc_relay_peer_count"],
        "rtc_relay_peers": rtc_sessions["rtc_relay_peers"],
        "rtc_sessions": rtc_sessions["rtc_sessions"],
        "reason_codes": reason_codes,
    }
    status = (
        "ok"
        if nat_traversal_observed or dominant_udp_flow.get("bytes") or rtc_sessions["rtc_flow_candidate_count"] > 0
        else "no_observations"
    )
    return {"status": status, "summary": summary}


def _summarize_stun_turn(*, pcap_path: Path | None, tshark_path: str | None) -> dict[str, Any]:
    if not pcap_path or not tshark_path or not pcap_path.exists():
        return {
            "turn_allocate_request_count": 0,
            "turn_allocate_success_count": 0,
            "relay_endpoints": [],
            "mapped_addresses": [],
        }
    result = _run_command(
        [
            tshark_path,
            "-r",
            str(pcap_path),
            "-Y",
            "stun",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "stun.type",
            "-e",
            "stun.type.method",
            "-e",
            "stun.type.class",
            "-e",
            "stun.att.ipv4",
            "-e",
            "stun.att.port",
        ]
    )
    stdout = str(result.get("stdout") or "")
    if not stdout:
        return {
            "turn_allocate_request_count": 0,
            "turn_allocate_success_count": 0,
            "relay_endpoints": [],
            "mapped_addresses": [],
        }
    relay_counts: dict[tuple[str, int], int] = {}
    mapped_counts: dict[tuple[str, int], int] = {}
    allocate_request_count = 0
    allocate_success_count = 0
    for line in stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        _type, method, klass, ip, port_text = [str(part or "").strip() for part in parts[:5]]
        port = _safe_int(port_text)
        if method == "0x0003" and klass == "0x0000":
            allocate_request_count += 1
            if ip and port is not None:
                relay_counts[(ip, port)] = relay_counts.get((ip, port), 0) + 1
        elif method == "0x0003" and klass == "0x0010":
            allocate_success_count += 1
            if ip and port is not None:
                mapped_counts[(ip, port)] = mapped_counts.get((ip, port), 0) + 1
    relay_endpoints = [
        {"ip": ip, "port": port, "allocate_count": count}
        for (ip, port), count in sorted(relay_counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    ]
    mapped_addresses = [
        {"ip": ip, "port": port, "observation_count": count}
        for (ip, port), count in sorted(mapped_counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    ]
    return {
        "turn_allocate_request_count": allocate_request_count,
        "turn_allocate_success_count": allocate_success_count,
        "relay_endpoints": relay_endpoints,
        "mapped_addresses": mapped_addresses,
    }


def _proto_bucket(report: dict[str, Any], bucket: str) -> dict[str, int]:
    agg = report.get("protocol_hierarchy_agg")
    if isinstance(agg, dict) and isinstance(agg.get(bucket), dict):
        return {str(k): _safe_int(v) or 0 for k, v in agg[bucket].items()}
    rows = report.get("protocol_hierarchy") if isinstance(report.get("protocol_hierarchy"), list) else []
    out: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        proto = str(row.get("protocol") or "").strip().lower()
        if not proto:
            continue
        out[proto] = out.get(proto, 0) + (_safe_int(row.get(bucket)) or 0)
    return out


def _summarize_rtc_sessions(*, pcap_path: Path | None, tshark_path: str | None) -> dict[str, Any]:
    if not pcap_path or not tshark_path or not pcap_path.exists():
        return {
            "rtc_flow_candidate_count": 0,
            "rtc_sustained_session_count": 0,
            "rtc_total_bytes": 0,
            "rtc_total_packets": 0,
            "rtc_stun_packet_count": 0,
            "rtc_dtls_packet_count": 0,
            "rtc_rtp_packet_count": 0,
            "rtc_srtcp_packet_count": 0,
            "rtc_quic_packet_count": 0,
            "rtc_max_session_bytes": 0,
            "rtc_max_session_duration_s": 0.0,
            "rtc_relay_peer_count": 0,
            "rtc_relay_peers": [],
            "rtc_sessions": [],
        }
    result = _run_command(
        [
            tshark_path,
            "-n",
            "-r",
            str(pcap_path),
            "-Y",
            "udp && (stun || dtls || rtp || srtcp || quic)",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "frame.time_relative",
            "-e",
            "ip.src",
            "-e",
            "udp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "udp.dstport",
            "-e",
            "frame.len",
            "-e",
            "frame.protocols",
        ]
    )
    stdout = str(result.get("stdout") or "")
    if not stdout:
        return {
            "rtc_flow_candidate_count": 0,
            "rtc_sustained_session_count": 0,
            "rtc_total_bytes": 0,
            "rtc_total_packets": 0,
            "rtc_stun_packet_count": 0,
            "rtc_dtls_packet_count": 0,
            "rtc_rtp_packet_count": 0,
            "rtc_srtcp_packet_count": 0,
            "rtc_quic_packet_count": 0,
            "rtc_max_session_bytes": 0,
            "rtc_max_session_duration_s": 0.0,
            "rtc_relay_peer_count": 0,
            "rtc_relay_peers": [],
            "rtc_sessions": [],
        }

    flows: dict[tuple[str, str], dict[str, Any]] = {}
    for raw_line in stdout.splitlines():
        parts = raw_line.split("\t")
        if len(parts) < 7:
            continue
        time_s = _safe_float(parts[0])
        src_ip = str(parts[1] or "").strip()
        src_port = _safe_int(parts[2])
        dst_ip = str(parts[3] or "").strip()
        dst_port = _safe_int(parts[4])
        frame_len = _safe_int(parts[5]) or 0
        protocols = str(parts[6] or "").strip().lower()
        if time_s is None or not src_ip or not dst_ip or src_port is None or dst_port is None:
            continue
        endpoint_a = f"{src_ip}:{src_port}"
        endpoint_b = f"{dst_ip}:{dst_port}"
        flow_key = tuple(sorted((endpoint_a, endpoint_b)))
        entry = flows.setdefault(
            flow_key,
            {
                "endpoint_a": flow_key[0],
                "endpoint_b": flow_key[1],
                "first_ts": time_s,
                "last_ts": time_s,
                "bytes": 0,
                "packets": 0,
                "stun_packets": 0,
                "dtls_packets": 0,
                "rtp_packets": 0,
                "srtcp_packets": 0,
                "quic_packets": 0,
            },
        )
        entry["first_ts"] = min(float(entry["first_ts"]), float(time_s))
        entry["last_ts"] = max(float(entry["last_ts"]), float(time_s))
        entry["bytes"] = int(entry["bytes"]) + max(frame_len, 0)
        entry["packets"] = int(entry["packets"]) + 1
        proto_set = set(protocols.split(":"))
        if "stun" in proto_set:
            entry["stun_packets"] = int(entry["stun_packets"]) + 1
        if "dtls" in proto_set:
            entry["dtls_packets"] = int(entry["dtls_packets"]) + 1
        if "rtp" in proto_set:
            entry["rtp_packets"] = int(entry["rtp_packets"]) + 1
        if "srtcp" in proto_set:
            entry["srtcp_packets"] = int(entry["srtcp_packets"]) + 1
        if "quic" in proto_set:
            entry["quic_packets"] = int(entry["quic_packets"]) + 1

    candidate_rows: list[dict[str, Any]] = []
    sustained_count = 0
    aggregate_bytes = 0
    aggregate_packets = 0
    total_stun_packets = 0
    total_dtls_packets = 0
    total_rtp_packets = 0
    total_srtcp_packets = 0
    total_quic_packets = 0
    max_session_bytes = 0
    max_session_duration_s = 0.0
    relay_peers: set[str] = set()
    for row in flows.values():
        duration_s = max(0.0, float(row["last_ts"]) - float(row["first_ts"]))
        has_rtc_signals = any(int(row.get(key) or 0) > 0 for key in ("stun_packets", "dtls_packets", "rtp_packets", "srtcp_packets"))
        flow_bytes = int(row.get("bytes") or 0)
        packet_count = int(row.get("packets") or 0)
        if not has_rtc_signals:
            continue
        if flow_bytes < 10_000 and packet_count < 25:
            continue
        aggregate_bytes += flow_bytes
        aggregate_packets += packet_count
        total_stun_packets += int(row.get("stun_packets") or 0)
        total_dtls_packets += int(row.get("dtls_packets") or 0)
        total_rtp_packets += int(row.get("rtp_packets") or 0)
        total_srtcp_packets += int(row.get("srtcp_packets") or 0)
        total_quic_packets += int(row.get("quic_packets") or 0)
        max_session_bytes = max(max_session_bytes, flow_bytes)
        max_session_duration_s = max(max_session_duration_s, duration_s)
        relay_peers.update(_public_peer_endpoints(row["endpoint_a"], row["endpoint_b"]))
        sustained = bool(
            duration_s >= 60.0
            and flow_bytes >= 200_000
            and (
                int(row.get("rtp_packets") or 0) > 0
                or int(row.get("srtcp_packets") or 0) > 0
                or int(row.get("stun_packets") or 0) >= 25
            )
        )
        if sustained:
            sustained_count += 1
        candidate_rows.append(
            {
                "endpoint_a": row["endpoint_a"],
                "endpoint_b": row["endpoint_b"],
                "first_ts": round(float(row["first_ts"]), 3),
                "last_ts": round(float(row["last_ts"]), 3),
                "duration_s": round(duration_s, 3),
                "bytes": flow_bytes,
                "packets": packet_count,
                "stun_packets": int(row.get("stun_packets") or 0),
                "dtls_packets": int(row.get("dtls_packets") or 0),
                "rtp_packets": int(row.get("rtp_packets") or 0),
                "srtcp_packets": int(row.get("srtcp_packets") or 0),
                "quic_packets": int(row.get("quic_packets") or 0),
                "sustained": sustained,
            }
        )

    candidate_rows.sort(
        key=lambda item: (
            not bool(item.get("sustained")),
            -int(item.get("bytes") or 0),
            -int(item.get("packets") or 0),
            float(item.get("first_ts") or 0.0),
        )
    )
    return {
        "rtc_flow_candidate_count": len(candidate_rows),
        "rtc_sustained_session_count": sustained_count,
        "rtc_total_bytes": aggregate_bytes,
        "rtc_total_packets": aggregate_packets,
        "rtc_stun_packet_count": total_stun_packets,
        "rtc_dtls_packet_count": total_dtls_packets,
        "rtc_rtp_packet_count": total_rtp_packets,
        "rtc_srtcp_packet_count": total_srtcp_packets,
        "rtc_quic_packet_count": total_quic_packets,
        "rtc_max_session_bytes": max_session_bytes,
        "rtc_max_session_duration_s": round(max_session_duration_s, 3),
        "rtc_relay_peer_count": len(relay_peers),
        "rtc_relay_peers": sorted(relay_peers)[:5],
        "rtc_sessions": candidate_rows[:5],
    }


def _select_dominant_udp_flow(top_flows: list[dict[str, Any]], *, udp_bytes: int) -> dict[str, Any]:
    udp_rows = [row for row in top_flows if isinstance(row, dict) and str(row.get("protocol") or "").lower() == "udp"]
    if not udp_rows:
        return {"status": "no_udp_top_flow"}
    row = max(udp_rows, key=lambda item: (_safe_int(item.get("bytes")) or 0, _safe_int(item.get("packets")) or 0))
    bytes_total = _safe_int(row.get("bytes")) or 0
    return {
        "status": "ok",
        "endpoint_a": row.get("endpoint_a"),
        "endpoint_b": row.get("endpoint_b"),
        "packets": _safe_int(row.get("packets")),
        "bytes": bytes_total,
        "directionality": row.get("directionality"),
        "share_of_udp_bytes": _bounded_ratio(bytes_total, udp_bytes),
    }


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bounded_ratio(numer: int | None, denom: int | None) -> float | None:
    if numer is None or denom is None or denom <= 0 or numer < 0:
        return None
    value = float(numer) / float(denom)
    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


def _public_peer_endpoints(endpoint_a: object, endpoint_b: object) -> list[str]:
    out: list[str] = []
    for endpoint in (endpoint_a, endpoint_b):
        endpoint_text = str(endpoint or "").strip()
        ip_text = endpoint_text.rsplit(":", 1)[0].strip() if ":" in endpoint_text else endpoint_text
        if endpoint_text and _is_public_ip(ip_text) and endpoint_text not in out:
            out.append(endpoint_text)
    return out


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


__all__ = ["summarize_media_plane"]


def _run_command(cmd: list[str]) -> dict[str, object]:
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception as exc:  # noqa: BLE001
        return {"stdout": "", "stderr": "", "error": str(exc)}
    return {
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
        "error": None if completed.returncode == 0 else completed.stderr.strip() or "command_failed",
    }
