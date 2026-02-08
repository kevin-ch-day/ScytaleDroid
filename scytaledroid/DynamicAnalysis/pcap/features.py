"""PCAP feature extraction for ML-ready dynamic runs."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap.timeseries import scan_pcap_timeseries_and_destinations


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
    features = _extract_features(report, cfg, operator=(manifest.operator or {}), target=(manifest.target or {}))
    if not features:
        _log(event_logger, "pcap_features_skip", {"reason": "pcap_features_empty"})
        return None

    # Optional enrichment from the PCAP itself (metadata only; no payload inspection).
    # This produces window-ready per-second summaries and destination diversity counts.
    _enrich_features_from_pcap(features, report, run_dir, event_logger=event_logger)

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


def _extract_features(
    report: dict[str, Any],
    cfg: PcapFeatureConfig,
    *,
    operator: dict[str, Any] | None = None,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
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

    # Derived intensity metrics (stable, comparable across apps/durations).
    bytes_per_sec = None
    packets_per_sec = None
    if duration_s and duration_s > 0:
        if data_bytes is not None:
            try:
                bytes_per_sec = float(data_bytes) / float(duration_s)
            except Exception:
                bytes_per_sec = None
        if packet_count is not None:
            try:
                packets_per_sec = float(packet_count) / float(duration_s)
            except Exception:
                packets_per_sec = None

    def _proto_key(value: object) -> str | None:
        if not value or not isinstance(value, str):
            return None
        key = value.strip().lower()
        return key or None

    def _bounded_ratio(numer: int | None, denom: int | None) -> float | None:
        if numer is None or denom is None:
            return None
        if denom <= 0 or numer < 0:
            return None
        # tshark protocol hierarchy bytes are not strictly exclusive; due to parsing quirks
        # it is possible for child protocol byte counts to slightly exceed the parent.
        # Clamp to [0, 1] to keep the proxy interpretable and ML-safe.
        ratio = float(numer) / float(denom) if denom else None
        if ratio is None:
            return None
        if ratio < 0:
            return 0.0
        if ratio > 1:
            return 1.0
        return ratio

    # Transport mix proxies (no decryption; based on protocol hierarchy bytes).
    proto_bytes: dict[str, int] = {}
    for row in report.get("protocol_hierarchy") or []:
        if not isinstance(row, dict):
            continue
        proto = _proto_key(row.get("protocol"))
        b = row.get("bytes")
        if not proto:
            continue
        try:
            bi = int(b)
        except Exception:
            continue
        proto_bytes[proto] = proto_bytes.get(proto, 0) + bi

    ip_bytes = proto_bytes.get("ip") or proto_bytes.get("frame") or None
    tcp_bytes = proto_bytes.get("tcp")
    udp_bytes = proto_bytes.get("udp")
    tls_bytes = proto_bytes.get("tls")
    quic_bytes = int((proto_bytes.get("quic") or 0) + (proto_bytes.get("gquic") or 0))

    tcp_ratio = _bounded_ratio(tcp_bytes, ip_bytes)
    udp_ratio = _bounded_ratio(udp_bytes, ip_bytes)
    # Use max(parent, child) as denominator to avoid >1 ratios if tshark reports slightly
    # inconsistent byte counts.
    quic_ratio = _bounded_ratio(quic_bytes, max(int(udp_bytes or 0), int(quic_bytes or 0)) or None)
    # For TLS, use TCP as the denominator (\"how much of TCP looks encrypted\").
    # tshark's protocol hierarchy byte counts can be non-exclusive, so TLS bytes can
    # exceed TCP bytes. Clamp by capping the numerator at the TCP total.
    tls_bytes_capped = None
    if tls_bytes is not None and tcp_bytes is not None:
        tls_bytes_capped = min(int(tls_bytes), int(tcp_bytes))
    tls_ratio = _bounded_ratio(tls_bytes_capped, tcp_bytes)

    # Domain diversity proxy (top-N limited; full domain list lives in overlap report).
    unique_domains_topn = len({str(item.get("value")).strip() for item in (top_sni + top_dns) if item.get("value")})
    # Report-level totals (computed in pcap_report.json when tshark is available).
    sni_obs = _safe_int(report.get("sni_observation_count"))
    dns_obs = _safe_int(report.get("dns_observation_count"))
    sni_unique = _safe_int(report.get("sni_unique_count"))
    dns_unique = _safe_int(report.get("dns_unique_count"))
    top1_sni_share = _safe_float(report.get("top1_sni_share"))
    top1_dns_share = _safe_float(report.get("top1_dns_share"))

    # Unique-per-minute proxy. This is not "new over time"; it is a stable diversity rate.
    domains_per_min = None
    new_sni_rate_per_min = None
    new_dns_rate_per_min = None
    if duration_s and duration_s > 0:
        try:
            denom = float(duration_s) / 60.0
            if denom > 0 and (sni_unique is not None or dns_unique is not None):
                domains_per_min = float((sni_unique or 0) + (dns_unique or 0)) / denom
            if denom > 0 and sni_unique is not None:
                new_sni_rate_per_min = float(sni_unique or 0) / denom
            if denom > 0 and dns_unique is not None:
                new_dns_rate_per_min = float(dns_unique or 0) / denom
        except Exception:
            domains_per_min = None
            new_sni_rate_per_min = None
            new_dns_rate_per_min = None
    return {
        # Backwards-compatible feature schema tag (Paper #2). New keys must only be
        # appended; existing key semantics must not change.
        "feature_schema_version": "v1.1",
        "metrics": {
            "packet_count": packet_count,
            "data_size_bytes": data_bytes,
            "capture_duration_s": duration_s,
            "bytes_per_sec": bytes_per_sec,
            "packets_per_sec": packets_per_sec,
            "data_byte_rate_bps": byte_rate,
            "data_bit_rate_bps": bit_rate,
            "avg_packet_size_bytes": avg_packet_size,
            "avg_packet_rate_pps": avg_packet_rate,
        },
        "proxies": {
            "unique_sni_topn": unique_sni,
            "unique_dns_topn": unique_dns,
            "unique_domains_topn": unique_domains_topn,
            "unique_sni_count": sni_unique,
            "unique_dns_qname_count": dns_unique,
            "sni_observation_count": sni_obs,
            "dns_observation_count": dns_obs,
            "top1_sni_share": top1_sni_share,
            "top1_dns_share": top1_dns_share,
            "domains_per_min": domains_per_min,
            # Alias to match PM wording; this is "unique observed per minute"
            # (not a temporal "new vs old" time series).
            "new_domain_rate_per_min": domains_per_min,
            "new_sni_rate_per_min": new_sni_rate_per_min,
            "new_dns_rate_per_min": new_dns_rate_per_min,
            "top_sni_total": top_sni_total,
            "top_dns_total": top_dns_total,
            "sni_concentration": sni_concentration,
            "dns_concentration": dns_concentration,
            "tcp_ratio": tcp_ratio,
            "udp_ratio": udp_ratio,
            "quic_ratio": quic_ratio,
            "tls_ratio": tls_ratio,
        },
        "quality": {
            "report_status": report.get("report_status"),
            "missing_tools": report.get("missing_tools") or [],
            "pcap_valid": bool(report.get("report_status") == "ok"),
            "pcap_enrichment": {
                "status": "not_attempted",
                "reason": None,
            },
            "feature_schema_version": "v1.1",
            "protocol": {
                "run_profile": (operator or {}).get("run_profile"),
                "run_sequence": (operator or {}).get("run_sequence"),
                "interaction_level": (operator or {}).get("interaction_level"),
            },
            "static_context": {
                "tags": (target or {}).get("static_context_tags") or [],
                "summary": (target or {}).get("static_context") or {},
                "note": "Static context is advisory and excluded from behavioral modeling.",
            },
            "note": "Fields under quality are excluded from behavioral modeling.",
        },
    }


def _enrich_features_from_pcap(
    features: dict[str, Any],
    report: dict[str, Any],
    run_dir: Path,
    *,
    event_logger: RunEventLogger | None = None,
) -> None:
    """Best-effort enrichment from PCAP packet metadata.

    Adds window-ready per-second summaries and destination diversity counts:
    - bytes_per_second_{p50,p95,max}
    - packets_per_second_{p50,p95,max}
    - burstiness_{bytes,packets}_p95_over_p50
    - unique_dst_ip_count
    - unique_dst_port_count
    """
    quality = features.get("quality")
    if not isinstance(quality, dict):
        quality = {}
        features["quality"] = quality
    enrich = quality.get("pcap_enrichment")
    if not isinstance(enrich, dict):
        enrich = {"status": "not_attempted", "reason": None}
        quality["pcap_enrichment"] = enrich

    tshark_path = shutil.which("tshark")
    if not tshark_path:
        enrich["status"] = "skipped"
        enrich["reason"] = "tshark_missing"
        return
    rel = report.get("pcap_path")
    if not isinstance(rel, str) or not rel.strip():
        enrich["status"] = "skipped"
        enrich["reason"] = "pcap_path_missing"
        return
    pcap_path = run_dir / rel
    if not pcap_path.exists():
        enrich["status"] = "skipped"
        enrich["reason"] = "pcap_file_missing"
        return

    try:
        stats = scan_pcap_timeseries_and_destinations(pcap_path, tshark_path=tshark_path)
    except Exception as exc:  # noqa: BLE001
        enrich["status"] = "failed"
        enrich["reason"] = f"scan_failed:{exc}"
        _log(event_logger, "pcap_features_enrich_failed", {"error": str(exc)})
        return

    metrics = features.get("metrics")
    if not isinstance(metrics, dict):
        metrics = {}
        features["metrics"] = metrics
    proxies = features.get("proxies")
    if not isinstance(proxies, dict):
        proxies = {}
        features["proxies"] = proxies

    metrics.update(
        {
            "bytes_per_second_p50": stats.get("bytes_per_second_p50"),
            "bytes_per_second_p95": stats.get("bytes_per_second_p95"),
            "bytes_per_second_max": stats.get("bytes_per_second_max"),
            "packets_per_second_p50": stats.get("packets_per_second_p50"),
            "packets_per_second_p95": stats.get("packets_per_second_p95"),
            "packets_per_second_max": stats.get("packets_per_second_max"),
            "burstiness_bytes_p95_over_p50": stats.get("burstiness_bytes_p95_over_p50"),
            "burstiness_packets_p95_over_p50": stats.get("burstiness_packets_p95_over_p50"),
        }
    )
    proxies.update(
        {
            "unique_dst_ip_count": stats.get("unique_dst_ip_count"),
            "unique_dst_port_count": stats.get("unique_dst_port_count"),
        }
    )
    enrich["status"] = "ok"
    enrich["reason"] = None


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
