from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.features import PcapFeatureConfig, _extract_features


def test_pcap_features_include_intensity_and_transport_ratios() -> None:
    report = {
        "report_status": "ok",
        "missing_tools": [],
        "capinfos": {
            "parsed": {
                "packet_count": 100,
                "data_size_bytes": 1000,
                "capture_duration_s": 10.0,
                "avg_packet_rate_pps": 10.0,
            }
        },
        "protocol_hierarchy": [
            {"protocol": "ip", "bytes": 1000, "frames": 100},
            {"protocol": "tcp", "bytes": 800, "frames": 80},
            {"protocol": "udp", "bytes": 200, "frames": 20},
            {"protocol": "tls", "bytes": 400, "frames": 40},
            {"protocol": "quic", "bytes": 100, "frames": 10},
        ],
        "top_sni": [{"value": "pagead2.googlesyndication.com", "count": 5}],
        "top_dns": [{"value": "collector.cdp.cnn.com", "count": 4}],
        "transport_health": {
            "issue_packet_ratio": 0.12,
            "reset_packet_ratio": 0.03,
            "lifecycle_summary": {
                "reset_stream_ratio": 0.25,
                "clean_close_stream_ratio": 0.5,
                "partial_stream_ratio": 0.25,
                "issue_stream_ratio": 0.5,
            },
        },
        "tls_fingerprints": {
            "client_hello_count": 3,
            "server_hello_count": 2,
            "unique_ja3_count": 2,
            "unique_ja4_count": 2,
            "unique_ja3s_count": 1,
            "top1_ja3_share": 2.0 / 3.0,
            "top1_ja4_share": 2.0 / 3.0,
            "top1_ja3s_share": 1.0,
        },
        "media_plane": {
            "status": "ok",
            "summary": {
                "stun_frame_count": 480,
                "stun_frame_share_of_udp": 0.01,
                "turn_allocate_request_count": 1,
                "turn_allocate_success_count": 1,
                "relay_endpoint_count": 1,
                "relay_media_likely": True,
                "dominant_udp_flow": {"bytes": 900, "share_of_udp_bytes": 0.9},
            },
        },
        "startup_profile": {
            "window_s": 60,
            "startup_total_bytes": 960,
            "startup_total_packets": 96,
            "startup_byte_share": 0.96,
            "startup_packet_share": 0.96,
            "post_start_total_bytes": 40,
            "post_start_total_packets": 4,
            "post_start_minutes": 1,
            "post_start_median_bytes_per_min": 40.0,
            "post_start_mean_bytes_per_min": 40.0,
            "post_start_median_packets_per_min": 4.0,
            "post_start_mean_packets_per_min": 4.0,
            "startup_dominant": True,
        },
    }
    out = _extract_features(
        report,
        PcapFeatureConfig(),
        operator={"run_profile": "interactive_use"},
        target={"package_name": "com.cnn.mobile.android.phone"},
    )
    # Versioned feature contract: schema version may be emitted at the top level.
    assert {"metrics", "proxies", "quality"}.issubset(set(out.keys()))
    metrics = out["metrics"]
    proxies = out["proxies"]
    quality = out["quality"]

    assert metrics["bytes_per_sec"] == 100.0
    assert metrics["packets_per_sec"] == 10.0
    assert proxies["tcp_ratio"] == 0.8
    assert proxies["udp_ratio"] == 0.2
    assert proxies["quic_ratio"] == 0.5
    assert proxies["tls_ratio"] == 0.5
    assert proxies["tcp_issue_packet_ratio"] == 0.12
    assert proxies["tcp_reset_packet_ratio"] == 0.03
    assert proxies["tcp_reset_stream_ratio"] == 0.25
    assert proxies["tcp_clean_close_stream_ratio"] == 0.5
    assert proxies["tcp_partial_stream_ratio"] == 0.25
    assert proxies["tcp_issue_stream_ratio"] == 0.5
    assert proxies["tls_client_hello_count"] == 3
    assert proxies["tls_server_hello_count"] == 2
    assert proxies["unique_ja3_count"] == 2
    assert proxies["unique_ja4_count"] == 2
    assert proxies["unique_ja3s_count"] == 1
    assert proxies["top1_ja3_share"] == 2.0 / 3.0
    assert proxies["stun_frame_count"] == 480
    assert proxies["turn_allocate_success_count"] == 1
    assert proxies["dominant_udp_flow_share"] == 0.9
    assert proxies["relay_media_detected"] == 1
    assert proxies["startup_byte_share"] == 0.96
    assert proxies["post_start_median_bytes_per_min"] == 40.0
    assert proxies["startup_dominant"] == 1
    assert proxies["unique_domains_topn"] == 2
    assert proxies["first_party_service_hits"] == 4
    assert proxies["third_party_service_hits"] == 5
    assert proxies["privacy_signal_hits"] == 10
    assert quality["pcap_valid"] is True
    assert out["service_context"]["status"] == "ok"
    assert out["service_signals"]["status"] == "ok"
    assert out["service_context"]["summary"]["service_count"] >= 2


def test_pcap_feature_enrichment_appends_direction_flow_burst_and_visibility(monkeypatch, tmp_path: Path) -> None:
    from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
    from scytaledroid.DynamicAnalysis.pcap.features import write_pcap_features

    run_dir = tmp_path / "run-1"
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "pcap_path": "artifacts/pcapdroid_capture/app.pcap",
                "report_status": "ok",
                "missing_tools": [],
                "capinfos": {"parsed": {"packet_count": 10, "data_size_bytes": 1000, "capture_duration_s": 10.0}},
                "protocol_hierarchy": [],
                "top_sni": [],
                "top_dns": [],
                "transport_health": {
                    "tcp_packet_count": 10,
                    "issue_packet_count": 2,
                    "issue_packet_ratio": 0.2,
                    "lifecycle_summary": {"reset_stream_ratio": 0.5},
                    "top_streams": [{"tcp_stream": "7", "issue_packets": 2}],
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True)
    (run_dir / "artifacts" / "pcapdroid_capture" / "app.pcap").write_bytes(b"pcap")

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.features.scan_pcap_timeseries_and_destinations",
        lambda *args, **kwargs: {
            "bytes_per_second_p50": 10.0,
            "bytes_per_second_p95": 20.0,
            "bytes_per_second_max": 30.0,
            "packets_per_second_p50": 1.0,
            "packets_per_second_p95": 2.0,
            "packets_per_second_max": 3.0,
            "burstiness_bytes_p95_over_p50": 2.0,
            "burstiness_packets_p95_over_p50": 2.0,
            "unique_dst_ip_count": 4,
            "unique_dst_port_count": 3,
            "direction_summary": {"outbound_packets": 5, "inbound_packets": 4, "unknown_packets": 1},
            "flow_summary": {"flow_count": 2, "top_flows": []},
            "burst_summary": {"burst_count": 2, "active_second_count": 2},
            "startup_profile": {
                "window_s": 60,
                "startup_total_bytes": 1000,
                "startup_total_packets": 10,
                "startup_byte_share": 0.83,
                "startup_packet_share": 0.83,
                "post_start_total_bytes": 200,
                "post_start_total_packets": 2,
                "post_start_minutes": 2,
                "post_start_median_bytes_per_min": 100.0,
                "post_start_mean_bytes_per_min": 100.0,
                "post_start_median_packets_per_min": 1.0,
                "post_start_mean_packets_per_min": 1.0,
                "startup_dominant": True,
            },
            "tls_quic_visibility": {"tls_handshake_packets": 2, "quic_candidate_packets": 1},
            "window_metrics": {
                "180s": {
                    "window_s": 180,
                    "total_bytes": 1200,
                    "total_packets": 12,
                    "avg_bytes_per_sec": 6.6667,
                    "avg_packets_per_sec": 0.0667,
                    "bytes_per_second_p95": 25.0,
                    "packets_per_second_p95": 2.0,
                    "active_second_count": 8,
                    "active_second_ratio": 8 / 180.0,
                },
                "240s": {
                    "window_s": 240,
                    "total_bytes": 1500,
                    "total_packets": 15,
                    "avg_bytes_per_sec": 6.25,
                    "avg_packets_per_sec": 0.0625,
                    "bytes_per_second_p95": 22.0,
                    "packets_per_second_p95": 2.0,
                    "active_second_count": 10,
                    "active_second_ratio": 10 / 240.0,
                },
            },
        },
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-15T00:00:00Z",
        target={"package_name": "bbc.mobile.news.ww"},
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/app.pcap",
                type="pcapdroid_capture",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    artifact = write_pcap_features(manifest, run_dir, config=PcapFeatureConfig())
    assert artifact is not None

    payload = json.loads((run_dir / "analysis" / "pcap_features.json").read_text(encoding="utf-8"))
    assert payload["quality"]["capture_identity"]["dynamic_run_id"] == "run-1"
    assert payload["quality"]["capture_identity"]["package_name"] == "bbc.mobile.news.ww"
    assert payload["quality"]["capture_identity"]["package_slug"] == "bbc_mobile_news_ww"
    assert payload["quality"]["capture_identity"]["pcap_capture_name"] == "app.pcap"
    assert payload["direction"]["status"] == "ok"
    assert payload["direction"]["summary"]["outbound_packets"] == 5
    assert payload["flows"]["summary"]["flow_count"] == 2
    assert payload["bursts"]["summary"]["burst_count"] == 2
    assert payload["startup_profile"]["summary"]["startup_byte_share"] == 0.83
    assert payload["visibility"]["summary"]["tls_handshake_packets"] == 2
    assert payload["window_metrics"]["180s"]["total_bytes"] == 1200
    assert payload["window_metrics"]["240s"]["bytes_per_second_p95"] == 22.0
    assert payload["traffic_posture"]["status"] == "ok"
    assert payload["traffic_posture"]["summary"]["outbound_packet_ratio"] == 0.5
    assert payload["traffic_posture"]["summary"]["inbound_packet_ratio"] == 0.4
    assert payload["traffic_posture"]["summary"]["active_second_ratio"] == 0.2
    assert payload["traffic_posture"]["summary"]["tls_handshakes_per_min"] == 12.0
    assert payload["traffic_posture"]["summary"]["startup_byte_share"] == 0.83
    assert payload["traffic_posture"]["summary"]["startup_dominant"] is True
    assert payload["fingerprints"]["status"] == "not_attempted"
    assert payload["transport_health"]["status"] == "from_report"
    assert payload["transport_health"]["summary"]["issue_packet_count"] == 2
    assert payload["transport_health"]["summary"]["lifecycle_summary"]["reset_stream_ratio"] == 0.5
    assert payload["media_plane"]["status"] == "not_attempted"
    assert payload["service_context"]["status"] == "no_observations"
    assert payload["service_signals"]["status"] == "no_observations"
