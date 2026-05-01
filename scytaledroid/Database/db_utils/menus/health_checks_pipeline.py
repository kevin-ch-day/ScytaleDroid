"""Pipeline-connection helpers for DB health checks."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Database.db_core import run_sql


def fetch_pcap_backfill_candidates(limit: int = 25) -> tuple[list[dict[str, object]], int]:
    rows = run_sql(
        """
        SELECT dynamic_run_id, evidence_path
        FROM dynamic_sessions
        WHERE pcap_relpath IS NULL
          AND evidence_path IS NOT NULL
        ORDER BY started_at_utc DESC
        LIMIT %s
        """,
        (limit,),
        fetch="all",
        dictionary=True,
    ) or []
    count_row = run_sql(
        """
        SELECT COUNT(*)
        FROM dynamic_sessions
        WHERE pcap_relpath IS NULL
          AND evidence_path IS NOT NULL
        """,
        fetch="one",
    )
    count = int((count_row or [0])[0] or 0)
    return rows, count


def load_pcap_summary_fields(evidence_path: str) -> tuple[object, object, object, object]:
    summary_path = Path(str(evidence_path)) / "analysis" / "summary.json"
    if not summary_path.exists():
        return None, None, None, None
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception:
        return None, None, None, None

    capture = payload.get("capture") or {}
    evidence = payload.get("evidence") or []
    pcap_relpath = None
    pcap_sha256 = None
    pcap_bytes = None
    for entry in evidence:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") in {"pcapdroid_capture", "network_capture", "proxy_capture"}:
            pcap_relpath = entry.get("relative_path")
            pcap_sha256 = entry.get("sha256")
            pcap_bytes = entry.get("size_bytes")
            break
    if pcap_bytes is None and isinstance(capture, dict):
        pcap_bytes = capture.get("pcap_size_bytes")
    pcap_valid = capture.get("pcap_valid") if isinstance(capture, dict) else None
    return pcap_relpath, pcap_sha256, pcap_bytes, pcap_valid
