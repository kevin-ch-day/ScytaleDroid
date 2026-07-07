"""PCAP feature extraction for ML-ready dynamic runs."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap.context_summary import summarize_pcap_service_context
from scytaledroid.DynamicAnalysis.pcap.identity import ensure_features_capture_identity
from scytaledroid.DynamicAnalysis.pcap.posture import summarize_traffic_posture
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
    features = _extract_features(
        report,
        cfg,
        operator=(manifest.operator or {}),
        target=(manifest.target or {}),
        dynamic_run_id=manifest.dynamic_run_id,
    )
    if not features:
        _log(event_logger, "pcap_features_skip", {"reason": "pcap_features_empty"})
        return None

    # Optional enrichment from the PCAP itself (metadata only; no payload inspection).
    # This produces window-ready per-second summaries and destination diversity counts.
    _enrich_features_from_pcap(features, report, run_dir, event_logger=event_logger)
    ensure_features_capture_identity(
        features,
        dynamic_run_id=manifest.dynamic_run_id,
        package_name=str((manifest.target or {}).get("package_name") or "").strip() or None,
        app_label=str((manifest.target or {}).get("display_name") or (manifest.target or {}).get("app_label") or "").strip() or None,
        report=report,
    )
    _refresh_traffic_posture(features)

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
    dynamic_run_id: str | None = None,
) -> dict[str, Any]:
    package_name = str((target or {}).get("package_name") or (target or {}).get("package") or "").strip().lower()
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
    transport_health = report.get("transport_health") or {}
    issue_packet_ratio = _safe_float(transport_health.get("issue_packet_ratio")) if isinstance(transport_health, dict) else None
    reset_packet_ratio = _safe_float(transport_health.get("reset_packet_ratio")) if isinstance(transport_health, dict) else None
    lifecycle_summary = (
        transport_health.get("lifecycle_summary")
        if isinstance(transport_health, dict) and isinstance(transport_health.get("lifecycle_summary"), dict)
        else {}
    )
    fingerprint_summary = (
        report.get("tls_fingerprints")
        if isinstance(report.get("tls_fingerprints"), dict)
        else {}
    )
    context_bundle = summarize_pcap_service_context(report, package_name=package_name)
    service_context = context_bundle.get("service_context") or {}
    service_signals = context_bundle.get("service_signals") or {}
    media_plane = report.get("media_plane") if isinstance(report.get("media_plane"), dict) else {}
    media_plane_summary = media_plane.get("summary") if isinstance(media_plane.get("summary"), dict) else {}
    startup_profile = report.get("startup_profile") if isinstance(report.get("startup_profile"), dict) else {}
    dominant_udp_flow = (
        media_plane_summary.get("dominant_udp_flow")
        if isinstance(media_plane_summary.get("dominant_udp_flow"), dict)
        else {}
    )
    owner_hits = service_context.get("owner_class_hit_counts") if isinstance(service_context, dict) else {}
    focus_hits = service_signals.get("focus_area_hit_counts") if isinstance(service_signals, dict) else {}
    severity_hits = service_signals.get("severity_hit_counts") if isinstance(service_signals, dict) else {}
    surface = report.get("security_surface") if isinstance(report.get("security_surface"), dict) else {}
    cleartext_surface = surface.get("cleartext") if isinstance(surface.get("cleartext"), dict) else {}
    dns_surface = surface.get("dns_anomalies") if isinstance(surface.get("dns_anomalies"), dict) else {}
    tls_surface = surface.get("tls_surface") if isinstance(surface.get("tls_surface"), dict) else {}
    threat_surface = surface.get("threat_heuristics") if isinstance(surface.get("threat_heuristics"), dict) else {}
    surface_ok = str(surface.get("status") or "") == "ok"
    return {
        # Backwards-compatible feature schema tag (Paper #2). New keys must only be
        # appended; existing key semantics must not change.
        "feature_schema_version": "v1.3",
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
            "tcp_issue_packet_ratio": issue_packet_ratio,
            "tcp_reset_packet_ratio": reset_packet_ratio,
            "tcp_reset_stream_ratio": _safe_float(lifecycle_summary.get("reset_stream_ratio")),
            "tcp_clean_close_stream_ratio": _safe_float(lifecycle_summary.get("clean_close_stream_ratio")),
            "tcp_partial_stream_ratio": _safe_float(lifecycle_summary.get("partial_stream_ratio")),
            "tcp_issue_stream_ratio": _safe_float(lifecycle_summary.get("issue_stream_ratio")),
            "tls_client_hello_count": _safe_int(fingerprint_summary.get("client_hello_count")),
            "tls_server_hello_count": _safe_int(fingerprint_summary.get("server_hello_count")),
            "unique_ja3_count": _safe_int(fingerprint_summary.get("unique_ja3_count")),
            "unique_ja4_count": _safe_int(fingerprint_summary.get("unique_ja4_count")),
            "unique_ja3s_count": _safe_int(fingerprint_summary.get("unique_ja3s_count")),
            "top1_ja3_share": _safe_float(fingerprint_summary.get("top1_ja3_share")),
            "top1_ja4_share": _safe_float(fingerprint_summary.get("top1_ja4_share")),
            "top1_ja3s_share": _safe_float(fingerprint_summary.get("top1_ja3s_share")),
            "first_party_service_hits": _safe_int((owner_hits or {}).get("first_party")) if isinstance(owner_hits, dict) else None,
            "third_party_service_hits": _safe_int((owner_hits or {}).get("third_party")) if isinstance(owner_hits, dict) else None,
            "privacy_signal_hits": _safe_int((focus_hits or {}).get("privacy")) if isinstance(focus_hits, dict) else None,
            "high_severity_signal_hits": _safe_int((severity_hits or {}).get("high")) if isinstance(severity_hits, dict) else None,
            "stun_frame_count": _safe_int(media_plane_summary.get("stun_frame_count")),
            "stun_frame_share_of_udp": _safe_float(media_plane_summary.get("stun_frame_share_of_udp")),
            "turn_allocate_request_count": _safe_int(media_plane_summary.get("turn_allocate_request_count")),
            "turn_allocate_success_count": _safe_int(media_plane_summary.get("turn_allocate_success_count")),
            "relay_endpoint_count": _safe_int(media_plane_summary.get("relay_endpoint_count")),
            "rtc_flow_candidate_count": _safe_int(media_plane_summary.get("rtc_flow_candidate_count")),
            "rtc_sustained_session_count": _safe_int(media_plane_summary.get("rtc_sustained_session_count")),
            "rtc_total_bytes": _safe_int(media_plane_summary.get("rtc_total_bytes")),
            "rtc_total_packets": _safe_int(media_plane_summary.get("rtc_total_packets")),
            "rtc_stun_packet_count": _safe_int(media_plane_summary.get("rtc_stun_packet_count")),
            "rtc_dtls_packet_count": _safe_int(media_plane_summary.get("rtc_dtls_packet_count")),
            "rtc_rtp_packet_count": _safe_int(media_plane_summary.get("rtc_rtp_packet_count")),
            "rtc_srtcp_packet_count": _safe_int(media_plane_summary.get("rtc_srtcp_packet_count")),
            "rtc_quic_packet_count": _safe_int(media_plane_summary.get("rtc_quic_packet_count")),
            "rtc_max_session_bytes": _safe_int(media_plane_summary.get("rtc_max_session_bytes")),
            "rtc_max_session_duration_s": _safe_float(media_plane_summary.get("rtc_max_session_duration_s")),
            "rtc_relay_peer_count": _safe_int(media_plane_summary.get("rtc_relay_peer_count")),
            "dominant_udp_flow_bytes": _safe_int(dominant_udp_flow.get("bytes")) if isinstance(dominant_udp_flow, dict) else None,
            "dominant_udp_flow_share": _safe_float(dominant_udp_flow.get("share_of_udp_bytes")) if isinstance(dominant_udp_flow, dict) else None,
            "relay_media_detected": 1 if media_plane_summary.get("relay_media_likely") else 0 if media_plane else None,
            "rtc_call_observed": 1 if media_plane_summary.get("rtc_call_observed") else 0 if media_plane else None,
            "rtc_multi_session_observed": 1 if media_plane_summary.get("rtc_multi_session_observed") else 0 if media_plane else None,
            "startup_byte_share": _safe_float(startup_profile.get("startup_byte_share")),
            "startup_packet_share": _safe_float(startup_profile.get("startup_packet_share")),
            "post_start_median_bytes_per_min": _safe_float(startup_profile.get("post_start_median_bytes_per_min")),
            "post_start_mean_bytes_per_min": _safe_float(startup_profile.get("post_start_mean_bytes_per_min")),
            "post_start_median_packets_per_min": _safe_float(startup_profile.get("post_start_median_packets_per_min")),
            "post_start_mean_packets_per_min": _safe_float(startup_profile.get("post_start_mean_packets_per_min")),
            "startup_dominant": 1 if startup_profile.get("startup_dominant") else 0 if startup_profile else None,
            "security_finding_count": _safe_int(surface.get("finding_count")) if surface_ok else None,
            "security_risk_flag_count": len(surface.get("risk_flags") or []) if surface_ok else None,
            "cleartext_http_observed": 1 if cleartext_surface.get("http_observed") else 0 if surface_ok else None,
            "cleartext_protocol_observed": (
                1 if cleartext_surface.get("cleartext_protocol_observed") else 0 if surface_ok else None
            ),
            "plaintext_protocols_observed": (
                ";".join(cleartext_surface.get("plaintext_protocols_observed") or []) if surface_ok else None
            ),
            "decoded_protocols_observed": (
                ";".join(cleartext_surface.get("decoded_protocols_observed") or []) if surface_ok else None
            ),
            "plaintext_protocol_frames": _safe_int(cleartext_surface.get("plaintext_protocol_frames")) if surface_ok else None,
            "dns_nxdomain_responses": _safe_int(dns_surface.get("nxdomain_responses")) if surface_ok else None,
            "dns_txt_queries": _safe_int(dns_surface.get("txt_queries")) if surface_ok else None,
            "tls_alert_count": _safe_int(tls_surface.get("tls_alert_count")) if surface_ok else None,
            "tls_self_signed_count": _safe_int(tls_surface.get("self_signed_count")) if surface_ok else None,
            "security_heuristic_score": _safe_int(threat_surface.get("heuristic_score")) if surface_ok else None,
            "decoded_cleartext_stream_count": _safe_int(cleartext_surface.get("decoded_stream_count")) if surface_ok else None,
        },
        "quality": {
            "report_status": report.get("report_status"),
            "missing_tools": report.get("missing_tools") or [],
            "pcap_valid": bool(report.get("report_status") == "ok"),
            "pcap_enrichment": {
                "status": "not_attempted",
                "reason": None,
            },
            "feature_schema_version": "v1.3",
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
        "direction": {
            "status": "not_attempted",
            "summary": {},
        },
        "flows": {
            "status": "not_attempted",
            "summary": {},
        },
        "bursts": {
            "status": "not_attempted",
            "summary": {},
        },
        "visibility": {
            "status": "not_attempted",
            "summary": {},
        },
        "startup_profile": {
            "status": "ok" if startup_profile else "not_attempted",
            "summary": startup_profile if isinstance(startup_profile, dict) else {},
        },
        "traffic_posture": {
            "status": "not_attempted",
            "summary": {},
        },
        "fingerprints": {
            "status": "ok" if isinstance(fingerprint_summary, dict) and fingerprint_summary else "not_attempted",
            "summary": fingerprint_summary if isinstance(fingerprint_summary, dict) else {},
        },
        "transport_health": {
            "status": "from_report" if isinstance(transport_health, dict) and transport_health else "not_attempted",
            "summary": transport_health if isinstance(transport_health, dict) else {},
        },
        "service_context": {
            "status": str(service_context.get("status") or "not_attempted") if isinstance(service_context, dict) else "not_attempted",
            "summary": service_context if isinstance(service_context, dict) else {},
        },
        "service_signals": {
            "status": str(service_signals.get("status") or "not_attempted") if isinstance(service_signals, dict) else "not_attempted",
            "summary": service_signals if isinstance(service_signals, dict) else {},
        },
        "media_plane": {
            "status": str(media_plane.get("status") or "not_attempted") if isinstance(media_plane, dict) else "not_attempted",
            "summary": media_plane_summary if isinstance(media_plane_summary, dict) else {},
        },
        "security_surface": {
            "status": str(surface.get("status") or "not_attempted") if surface else "not_attempted",
            "summary": {
                "finding_count": surface.get("finding_count"),
                "risk_flags": surface.get("risk_flags") or [],
                "cleartext_visibility_class": cleartext_surface.get("visibility_class"),
                "http_observed": cleartext_surface.get("http_observed"),
                "cleartext_protocol_observed": cleartext_surface.get("cleartext_protocol_observed"),
                "plaintext_protocols_observed": cleartext_surface.get("plaintext_protocols_observed") or [],
                "decoded_protocols_observed": cleartext_surface.get("decoded_protocols_observed") or [],
                "decoded_stream_count": cleartext_surface.get("decoded_stream_count"),
            }
            if surface_ok
            else {},
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
    direction = features.get("direction")
    if not isinstance(direction, dict):
        direction = {"status": "not_attempted", "summary": {}}
        features["direction"] = direction
    flows = features.get("flows")
    if not isinstance(flows, dict):
        flows = {"status": "not_attempted", "summary": {}}
        features["flows"] = flows
    bursts = features.get("bursts")
    if not isinstance(bursts, dict):
        bursts = {"status": "not_attempted", "summary": {}}
        features["bursts"] = bursts
    visibility = features.get("visibility")
    if not isinstance(visibility, dict):
        visibility = {"status": "not_attempted", "summary": {}}
        features["visibility"] = visibility
    startup = features.get("startup_profile")
    if not isinstance(startup, dict):
        startup = {"status": "not_attempted", "summary": {}}
        features["startup_profile"] = startup
    window_metrics = features.get("window_metrics")
    if not isinstance(window_metrics, dict):
        window_metrics = {}
        features["window_metrics"] = window_metrics

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
    direction["status"] = "ok"
    direction["summary"] = stats.get("direction_summary") or {}
    flows["status"] = "ok"
    flows["summary"] = stats.get("flow_summary") or {}
    bursts["status"] = "ok"
    bursts["summary"] = stats.get("burst_summary") or {}
    visibility["status"] = "ok"
    visibility["summary"] = stats.get("tls_quic_visibility") or {}
    startup["status"] = "ok"
    startup["summary"] = stats.get("startup_profile") or {}
    window_metrics.update(stats.get("window_metrics") or {})
    enrich["status"] = "ok"
    enrich["reason"] = None


def _refresh_traffic_posture(features: dict[str, Any]) -> None:
    posture = features.get("traffic_posture")
    if not isinstance(posture, dict):
        posture = {"status": "not_attempted", "summary": {}}
        features["traffic_posture"] = posture

    metrics = features.get("metrics") if isinstance(features.get("metrics"), dict) else {}
    direction = features.get("direction") if isinstance(features.get("direction"), dict) else {}
    flows = features.get("flows") if isinstance(features.get("flows"), dict) else {}
    bursts = features.get("bursts") if isinstance(features.get("bursts"), dict) else {}
    visibility = features.get("visibility") if isinstance(features.get("visibility"), dict) else {}
    startup = features.get("startup_profile") if isinstance(features.get("startup_profile"), dict) else {}

    summary = summarize_traffic_posture(
        metrics=metrics,
        direction_summary=direction.get("summary") if isinstance(direction.get("summary"), dict) else {},
        flow_summary=flows.get("summary") if isinstance(flows.get("summary"), dict) else {},
        burst_summary=bursts.get("summary") if isinstance(bursts.get("summary"), dict) else {},
        visibility_summary=visibility.get("summary") if isinstance(visibility.get("summary"), dict) else {},
        startup_summary=startup.get("summary") if isinstance(startup.get("summary"), dict) else {},
    )
    posture["summary"] = summary
    posture["status"] = "ok" if any(value is not None for value in summary.values()) else "not_attempted"


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
