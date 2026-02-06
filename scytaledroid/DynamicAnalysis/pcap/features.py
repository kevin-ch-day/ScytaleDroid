"""PCAP feature extraction for ML-ready dynamic runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest


@dataclass(frozen=True)
class PcapFeatureConfig:
    top_n: int = 10


def write_pcap_features(
    manifest: RunManifest,
    run_dir: Path,
    *,
    config: PcapFeatureConfig | None = None,
    event_logger: RunEventLogger | None = None,
) -> ArtifactRecord | None:
    cfg = config or PcapFeatureConfig()
    report_path = run_dir / "analysis/pcap_report.json"
    if not report_path.exists():
        _log(event_logger, "pcap_features_skip", {"reason": "pcap_report_missing"})
        return None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _log(event_logger, "pcap_features_skip", {"reason": "pcap_report_invalid"})
        return None
    features = _extract_features(report, cfg)
    if not features:
        _log(event_logger, "pcap_features_skip", {"reason": "pcap_features_empty"})
        return None
    output_path = run_dir / "analysis/pcap_features.json"
    output_path.write_text(json.dumps(features, indent=2, sort_keys=True), encoding="utf-8")
    return ArtifactRecord(
        relative_path=str(output_path.relative_to(run_dir)),
        type="pcap_features",
        sha256=_sha256(output_path),
        size_bytes=output_path.stat().st_size,
        produced_by="pcap_features",
        origin="host",
        pull_status="n/a",
    )


def _extract_features(report: dict[str, Any], cfg: PcapFeatureConfig) -> dict[str, Any]:
    capinfos = (report.get("capinfos") or {}).get("parsed") or {}
    packet_count = _safe_int(capinfos.get("packet_count"))
    data_bytes = _safe_int(capinfos.get("data_size_bytes"))
    duration_s = _safe_float(capinfos.get("capture_duration_s"))
    byte_rate = _safe_float(capinfos.get("data_byte_rate_bps"))
    bit_rate = _safe_float(capinfos.get("data_bit_rate_bps"))
    avg_packet_size = _safe_float(capinfos.get("avg_packet_size_bytes"))
    avg_packet_rate = _safe_float(capinfos.get("avg_packet_rate_pps"))
    top_sni = report.get("top_sni") or []
    top_dns = report.get("top_dns") or []
    unique_sni = len(top_sni)
    unique_dns = len(top_dns)
    top_sni_total = sum(int(item.get("count") or 0) for item in top_sni)
    top_dns_total = sum(int(item.get("count") or 0) for item in top_dns)
    sni_concentration = _concentration(top_sni, top_sni_total, cfg.top_n)
    dns_concentration = _concentration(top_dns, top_dns_total, cfg.top_n)
    return {
        "packet_count": packet_count,
        "data_size_bytes": data_bytes,
        "capture_duration_s": duration_s,
        "data_byte_rate_bps": byte_rate,
        "data_bit_rate_bps": bit_rate,
        "avg_packet_size_bytes": avg_packet_size,
        "avg_packet_rate_pps": avg_packet_rate,
        "unique_sni": unique_sni,
        "unique_dns": unique_dns,
        "top_sni_total": top_sni_total,
        "top_dns_total": top_dns_total,
        "sni_concentration": sni_concentration,
        "dns_concentration": dns_concentration,
        "report_status": report.get("report_status"),
        "missing_tools": report.get("missing_tools") or [],
    }


def _concentration(items: list[dict[str, Any]], total: int, top_n: int) -> float | None:
    if not items or total <= 0:
        return None
    top = items[: max(top_n, 1)]
    top_sum = sum(int(item.get("count") or 0) for item in top)
    return float(top_sum) / float(total) if total else None


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


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _log(event_logger: RunEventLogger | None, event: str, payload: dict[str, Any]) -> None:
    if event_logger:
        event_logger.log(event, payload)


__all__ = ["PcapFeatureConfig", "write_pcap_features"]
