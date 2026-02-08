"""Low-signal tagging for dynamic runs (Paper #2).

Contract (PM-locked):
- Validity (VALID/INVALID) is decided by QA rules and is independent of "signal quality".
- low_signal is a non-invalidating flag used to make ML preflight deterministic and auditable.

This module computes a low_signal decision from evidence-pack artifacts only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LowSignalConfig:
    """Deterministic thresholds for low-signal tagging.

    These defaults are intentionally conservative. The goal is to highlight runs
    that are "valid but likely uninformative for ML training" (e.g., extremely
    short capture span, near-empty PCAP, tiny packet counts).
    """

    min_capture_duration_s: float = 30.0
    min_data_size_bytes: int = 1_000_000  # ~1MB
    min_packet_count: int = 1_000
    min_unique_domains_topn: int = 3


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def compute_low_signal_from_evidence_pack(run_dir: Path, *, cfg: LowSignalConfig | None = None) -> dict[str, Any] | None:
    """Compute low_signal from pcap_features.json (preferred).

    Returns a dict that is safe to embed into run_manifest.json under dataset.
    If inputs are missing/unparseable, returns None.
    """

    config = cfg or LowSignalConfig()
    features_path = run_dir / "analysis" / "pcap_features.json"
    pf = _read_json(features_path)
    if not isinstance(pf, dict):
        return None

    metrics = pf.get("metrics") if isinstance(pf.get("metrics"), dict) else {}
    proxies = pf.get("proxies") if isinstance(pf.get("proxies"), dict) else {}

    capture_duration_s = metrics.get("capture_duration_s")
    data_size_bytes = metrics.get("data_size_bytes")
    packet_count = metrics.get("packet_count")
    unique_domains_topn = proxies.get("unique_domains_topn")

    reasons: list[str] = []

    try:
        dur = float(capture_duration_s) if capture_duration_s is not None else None
    except Exception:
        dur = None
    if dur is not None and dur < float(config.min_capture_duration_s):
        reasons.append("PCAP_CAPTURE_TOO_SHORT")

    try:
        size_b = int(data_size_bytes) if data_size_bytes is not None else None
    except Exception:
        size_b = None
    if size_b is not None and size_b < int(config.min_data_size_bytes):
        reasons.append("PCAP_BYTES_LOW")

    try:
        pkts = int(packet_count) if packet_count is not None else None
    except Exception:
        pkts = None
    if pkts is not None and pkts < int(config.min_packet_count):
        reasons.append("PCAP_PACKETS_LOW")

    try:
        doms = int(unique_domains_topn) if unique_domains_topn is not None else None
    except Exception:
        doms = None
    if doms is not None and doms < int(config.min_unique_domains_topn):
        reasons.append("DOMAINS_LOW")

    return {
        "low_signal": bool(reasons),
        "low_signal_reasons": reasons,
        "low_signal_thresholds": {
            "min_capture_duration_s": float(config.min_capture_duration_s),
            "min_data_size_bytes": int(config.min_data_size_bytes),
            "min_packet_count": int(config.min_packet_count),
            "min_unique_domains_topn": int(config.min_unique_domains_topn),
        },
    }


__all__ = ["LowSignalConfig", "compute_low_signal_from_evidence_pack"]

