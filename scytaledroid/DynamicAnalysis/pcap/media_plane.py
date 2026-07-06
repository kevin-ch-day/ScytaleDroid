"""PCAP media-plane understanding helpers.

This module stays payload-free and focuses on relay/call behavior that can be
inferred from protocol mix, STUN/TURN control messages, and dominant UDP flow
structure.
"""

from __future__ import annotations

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
        "reason_codes": reason_codes,
    }
    status = "ok" if nat_traversal_observed or dominant_udp_flow.get("bytes") else "no_observations"
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
