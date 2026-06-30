"""TCP transport-health extraction for saved PCAPs.

This module is intentionally bounded:
- offline only
- tshark field extraction only
- append-only summaries for report/features consumers
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

_EVENT_FIELDS: tuple[tuple[str, str], ...] = (
    ("retransmission", "tcp.analysis.retransmission"),
    ("fast_retransmission", "tcp.analysis.fast_retransmission"),
    ("spurious_retransmission", "tcp.analysis.spurious_retransmission"),
    ("out_of_order", "tcp.analysis.out_of_order"),
    ("duplicate_ack", "tcp.analysis.duplicate_ack"),
    ("lost_segment", "tcp.analysis.lost_segment"),
    ("zero_window", "tcp.analysis.zero_window"),
    ("zero_window_probe", "tcp.analysis.zero_window_probe"),
    ("zero_window_probe_ack", "tcp.analysis.zero_window_probe_ack"),
    ("window_full", "tcp.analysis.window_full"),
    ("window_update", "tcp.analysis.window_update"),
    ("keep_alive", "tcp.analysis.keep_alive"),
    ("keep_alive_ack", "tcp.analysis.keep_alive_ack"),
)

_LIFECYCLE_FIELDS: tuple[tuple[str, str], ...] = (
    ("syn", "tcp.flags.syn"),
    ("ack", "tcp.flags.ack"),
    ("fin", "tcp.flags.fin"),
)


def summarize_transport_health(pcap_path: Path, *, tshark_path: str | None = None) -> dict[str, Any]:
    tp = tshark_path or shutil.which("tshark")
    if not tp:
        raise RuntimeError("tshark_missing")
    if not pcap_path.exists():
        raise RuntimeError("pcap_missing")

    cmd = [
        tp,
        "-n",
        "-r",
        str(pcap_path),
        "-Y",
        "tcp",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "tcp.stream",
    ]
    for _, field in _EVENT_FIELDS:
        cmd.extend(["-e", field])
    cmd.extend(["-e", "tcp.flags.reset"])
    for _, field in _LIFECYCLE_FIELDS:
        cmd.extend(["-e", field])

    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "tshark_transport_health_failed")

    event_counts = {name: 0 for name, _ in _EVENT_FIELDS}
    stream_stats: dict[str, dict[str, int]] = {}
    tcp_packet_count = 0
    reset_packet_count = 0
    issue_packet_count = 0
    lifecycle_counts = {name: 0 for name, _ in _LIFECYCLE_FIELDS}

    for line in (completed.stdout or "").splitlines():
        parts = line.rstrip("\n").split("\t")
        if not parts:
            continue
        tcp_packet_count += 1
        stream_id = str(parts[0] or "").strip() or "unknown"
        stats = stream_stats.setdefault(
            stream_id,
            {
                "issue_packets": 0,
                "reset": 0,
                **{name: 0 for name, _ in _EVENT_FIELDS},
                **{name: 0 for name, _ in _LIFECYCLE_FIELDS},
            },
        )
        issue_seen = False

        for idx, (name, _field) in enumerate(_EVENT_FIELDS, start=1):
            if _truthy(parts[idx] if idx < len(parts) else ""):
                event_counts[name] += 1
                stats[name] += 1
                issue_seen = True

        reset_idx = 1 + len(_EVENT_FIELDS)
        if _truthy(parts[reset_idx] if reset_idx < len(parts) else ""):
            reset_packet_count += 1
            stats["reset"] += 1
            issue_seen = True

        for offset, (name, _field) in enumerate(_LIFECYCLE_FIELDS, start=1):
            lifecycle_idx = reset_idx + offset
            if _truthy(parts[lifecycle_idx] if lifecycle_idx < len(parts) else ""):
                lifecycle_counts[name] += 1
                stats[name] += 1

        if issue_seen:
            issue_packet_count += 1
            stats["issue_packets"] += 1

    top_streams = []
    ranked = sorted(
        stream_stats.items(),
        key=lambda item: (
            int(item[1].get("issue_packets", 0)),
            int(item[1].get("retransmission", 0)),
            int(item[1].get("reset", 0)),
        ),
        reverse=True,
    )
    for stream_id, stats in ranked[:5]:
        row = {"tcp_stream": stream_id}
        row.update({key: int(value) for key, value in stats.items()})
        top_streams.append(row)

    stream_count = len(stream_stats)
    issue_stream_count = 0
    reset_stream_count = 0
    clean_close_stream_count = 0
    partial_stream_count = 0
    handshake_seen_stream_count = 0
    for stats in stream_stats.values():
        saw_issue = int(stats.get("issue_packets", 0)) > 0
        saw_reset = int(stats.get("reset", 0)) > 0
        saw_fin = int(stats.get("fin", 0)) > 0
        saw_syn = int(stats.get("syn", 0)) > 0
        if saw_issue:
            issue_stream_count += 1
        if saw_reset:
            reset_stream_count += 1
        elif saw_fin:
            clean_close_stream_count += 1
        else:
            partial_stream_count += 1
        if saw_syn:
            handshake_seen_stream_count += 1

    issue_ratio = None
    reset_ratio = None
    if tcp_packet_count > 0:
        issue_ratio = float(issue_packet_count) / float(tcp_packet_count)
        reset_ratio = float(reset_packet_count) / float(tcp_packet_count)

    return {
        "analysis_basis": "tshark_tcp_analysis_fields",
        "tcp_packet_count": int(tcp_packet_count),
        "issue_packet_count": int(issue_packet_count),
        "issue_packet_ratio": issue_ratio,
        "reset_packet_count": int(reset_packet_count),
        "reset_packet_ratio": reset_ratio,
        "event_counts": event_counts,
        "affected_stream_count": int(issue_stream_count),
        "lifecycle_packet_counts": lifecycle_counts,
        "lifecycle_summary": {
            "stream_count": int(stream_count),
            "handshake_seen_stream_count": int(handshake_seen_stream_count),
            "issue_stream_count": int(issue_stream_count),
            "reset_stream_count": int(reset_stream_count),
            "clean_close_stream_count": int(clean_close_stream_count),
            "partial_stream_count": int(partial_stream_count),
            "issue_stream_ratio": (float(issue_stream_count) / float(stream_count)) if stream_count > 0 else None,
            "reset_stream_ratio": (float(reset_stream_count) / float(stream_count)) if stream_count > 0 else None,
            "clean_close_stream_ratio": (float(clean_close_stream_count) / float(stream_count)) if stream_count > 0 else None,
            "partial_stream_ratio": (float(partial_stream_count) / float(stream_count)) if stream_count > 0 else None,
        },
        "top_streams": top_streams,
    }


def _truthy(value: object) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return text not in {"0", "false"}


__all__ = ["summarize_transport_health"]
