from __future__ import annotations

import json


def test_build_dynamic_session_row_from_evidence_pack(tmp_path):
    from scytaledroid.DynamicAnalysis.storage.index_from_evidence import (
        build_dynamic_session_row_from_evidence_pack,
    )

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run123"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)

    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run123",
                "started_at": "2026-02-07T00:00:00Z",
                "ended_at": "2026-02-07T00:03:00Z",
                "status": "success",
                "target": {"package_name": "com.example.app"},
                "dataset": {"tier": "dataset", "duration_seconds": 180, "pcap_size_bytes": 1234},
                "operator": {"run_profile": "baseline_idle", "sampling_rate_s": 2},
                "artifacts": [{"type": "pcapdroid_capture", "relative_path": "inputs/app_only.pcapng"}],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps(
            {
                "static_run_id": 99,
                "package_name": "com.example.app",
                "version_code": 1,
                "version_name": "1.0",
                "run_identity": {"run_signature": "x", "run_signature_version": "v1"},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run123",
                "telemetry": {
                    "stats": {
                        "expected_samples": 90,
                        "captured_samples": 90,
                        "sample_max_gap_s": 2.4,
                    "netstats_missing_rows": 0,
                    "netstats_rows": 44,
                    "network_signal_quality": "netstats_ok",
                },
                    "quality": {"max_gap_s": 2.4, "avg_delta_s": 2.0},
                    "network_signal_quality": "netstats_ok",
                },
            }
        ),
        encoding="utf-8",
    )

    row = build_dynamic_session_row_from_evidence_pack(run_dir)
    assert row is not None
    assert row["dynamic_run_id"] == "run123"
    assert row["package_name"] == "com.example.app"
    assert row["static_run_id"] == 99
    assert row["static_handoff_hash"] is None
    assert row["pcap_bytes"] == 1234
    assert row["sampling_rate_s"] == 2
    assert row["expected_samples"] == 90
    assert row["captured_samples"] == 90
    assert row["sample_max_gap_s"] == 2.4
    assert row["netstats_missing_rows"] == 0
    assert row["netstats_rows"] == 44
    assert row["network_signal_quality"] == "netstats_ok"


def test_build_dynamic_session_row_includes_static_handoff_hash(tmp_path):
    from scytaledroid.DynamicAnalysis.storage.index_from_evidence import (
        build_dynamic_session_row_from_evidence_pack,
    )

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run124"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run124",
                "status": "success",
                "target": {"package_name": "com.example.app"},
                "dataset": {"tier": "dataset", "duration_seconds": 60, "pcap_size_bytes": 10},
                "operator": {"sampling_rate_s": 1},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps(
            {
                "static_run_id": 100,
                "package_name": "com.example.app",
                "run_identity": {
                    "run_signature": "x",
                    "run_signature_version": "v1",
                    "static_handoff_hash": "a" * 64,
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps({"dynamic_run_id": "run124", "telemetry": {"stats": {}, "quality": {}}}),
        encoding="utf-8",
    )
    row = build_dynamic_session_row_from_evidence_pack(run_dir)
    assert row is not None
    assert row["static_handoff_hash"] == "a" * 64


def test_build_dynamic_session_row_accepts_legacy_static_run_id_under_run_identity(tmp_path):
    from scytaledroid.DynamicAnalysis.storage.index_from_evidence import (
        build_dynamic_session_row_from_evidence_pack,
    )

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run125"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run125",
                "status": "success",
                "target": {"package_name": "com.example.legacy"},
                "dataset": {"tier": "dataset", "duration_seconds": 60},
                "operator": {"sampling_rate_s": 1},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps(
            {
                "package_name": "com.example.legacy",
                "run_identity": {
                    "static_run_id": 321,
                    "run_signature": "legacy-sig",
                    "run_signature_version": "v1",
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps({"dynamic_run_id": "run125", "telemetry": {"stats": {}, "quality": {}}}),
        encoding="utf-8",
    )

    row = build_dynamic_session_row_from_evidence_pack(run_dir)

    assert row is not None
    assert row["static_run_id"] == 321
    assert row["run_signature"] == "legacy-sig"


def test_build_dynamic_session_row_prefers_tracker_countability_truth(monkeypatch, tmp_path):
    from scytaledroid.DynamicAnalysis.storage import index_from_evidence

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run126"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run126",
                "status": "success",
                "target": {"package_name": "com.example.current"},
                "dataset": {
                    "tier": "dataset",
                    "countable": False,
                    "valid_dataset_run": True,
                    "invalid_reason_code": "EXTRA_RUN",
                },
                "operator": {"sampling_rate_s": 1},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps({"package_name": "com.example.current"}),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps({"dynamic_run_id": "run126", "telemetry": {"stats": {}, "quality": {}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        index_from_evidence,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                "com.example.current": {
                    "runs": [
                        {
                            "run_id": "run126",
                            "valid_dataset_run": True,
                            "counts_toward_quota": True,
                            "invalid_reason_code": None,
                        }
                    ]
                }
            }
        },
    )

    row = index_from_evidence.build_dynamic_session_row_from_evidence_pack(run_dir)

    assert row is not None
    assert row["countable"] == 1
    assert row["valid_dataset_run"] == 1
    assert row["invalid_reason_code"] is None


def test_build_dynamic_session_row_uses_paper_exclusion_reason_for_valid_supplemental_run(tmp_path):
    from scytaledroid.DynamicAnalysis.storage import index_from_evidence

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run126b"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run126b",
                "status": "success",
                "target": {"package_name": "com.example.current"},
                "dataset": {
                    "tier": "dataset",
                    "countable": False,
                    "valid_dataset_run": True,
                    "invalid_reason_code": None,
                    "paper_exclusion_primary_reason_code": "EXCLUDED_SCRIPT_ABORT",
                },
                "operator": {"sampling_rate_s": 1},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps({"package_name": "com.example.current"}),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps({"dynamic_run_id": "run126b", "telemetry": {"stats": {}, "quality": {}}}),
        encoding="utf-8",
    )

    row = index_from_evidence.build_dynamic_session_row_from_evidence_pack(run_dir)

    assert row is not None
    assert row["countable"] == 0
    assert row["valid_dataset_run"] == 1
    assert row["invalid_reason_code"] == "EXCLUDED_SCRIPT_ABORT"


def test_build_dynamic_network_features_row_prefers_tracker_countability_truth(monkeypatch, tmp_path):
    from scytaledroid.DynamicAnalysis.storage import index_from_evidence

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run127"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run127",
                "status": "success",
                "target": {"package_name": "com.example.current"},
                "dataset": {
                    "tier": "dataset",
                    "countable": False,
                    "valid_dataset_run": True,
                    "invalid_reason_code": "EXTRA_RUN",
                },
                "operator": {"sampling_rate_s": 1},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(
        json.dumps({"metrics": {}, "proxies": {}, "quality": {"protocol": {}}}),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(json.dumps({}), encoding="utf-8")
    monkeypatch.setattr(
        index_from_evidence,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                "com.example.current": {
                    "runs": [
                        {
                            "run_id": "run127",
                            "valid_dataset_run": True,
                            "counts_toward_quota": True,
                            "invalid_reason_code": None,
                        }
                    ]
                }
            }
        },
    )

    row = index_from_evidence.build_dynamic_network_features_row_from_evidence_pack(run_dir)

    assert row is not None
    assert row["countable"] == 1
    assert row["valid_dataset_run"] == 1
    assert row["invalid_reason_code"] is None


def test_build_dynamic_network_features_row_uses_paper_exclusion_reason_for_valid_supplemental_run(tmp_path):
    from scytaledroid.DynamicAnalysis.storage import index_from_evidence

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run127b"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run127b",
                "status": "success",
                "target": {"package_name": "com.example.current"},
                "dataset": {
                    "tier": "dataset",
                    "countable": False,
                    "valid_dataset_run": True,
                    "invalid_reason_code": None,
                    "paper_exclusion_primary_reason_code": "EXCLUDED_SCRIPT_ABORT",
                },
                "operator": {"sampling_rate_s": 1},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(
        json.dumps({"metrics": {}, "proxies": {}, "quality": {"protocol": {}}}),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(json.dumps({}), encoding="utf-8")

    row = index_from_evidence.build_dynamic_network_features_row_from_evidence_pack(run_dir)

    assert row is not None
    assert row["countable"] == 0
    assert row["valid_dataset_run"] == 1
    assert row["invalid_reason_code"] == "EXCLUDED_SCRIPT_ABORT"


def test_build_dynamic_network_features_row_recomputes_low_signal_for_messaging_call(tmp_path):
    from scytaledroid.DynamicAnalysis.storage import index_from_evidence

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run128"
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run128",
                "status": "success",
                "target": {"package_name": "com.whatsapp"},
                "dataset": {
                    "tier": "dataset",
                    "countable": False,
                    "valid_dataset_run": True,
                    "low_signal": True,
                    "low_signal_reasons": ["DOMAINS_LOW"],
                },
                "operator": {
                    "run_profile": "interaction_manual",
                    "interaction_level": "manual",
                    "messaging_activity": "voice_call",
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {
                    "capture_duration_s": 480.0,
                    "data_size_bytes": 1800000,
                    "packet_count": 11229,
                },
                "proxies": {
                    "udp_ratio": 0.96,
                    "unique_dst_ip_count": 7,
                    "unique_domains_topn": 1,
                },
                "quality": {
                    "protocol": {
                        "run_profile": "interaction_manual",
                        "interaction_level": "manual",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(json.dumps({}), encoding="utf-8")

    row = index_from_evidence.build_dynamic_network_features_row_from_evidence_pack(run_dir)

    assert row is not None
    assert row["valid_dataset_run"] == 1
    assert row["countable"] == 0
    assert row["low_signal"] == 0
    assert row["low_signal_reasons_json"] == "[]"


def test_build_dynamic_network_features_row_promotes_flow_and_tls_report_fields(tmp_path):
    from scytaledroid.DynamicAnalysis.storage import index_from_evidence

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run129"
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run129",
                "status": "success",
                "target": {"package_name": "com.example.network"},
                "dataset": {
                    "tier": "dataset",
                    "countable": True,
                    "valid_dataset_run": True,
                },
                "operator": {
                    "run_profile": "interaction_manual",
                    "interaction_level": "manual",
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {"capture_duration_s": 240.0},
                "proxies": {},
                "quality": {"protocol": {}},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "direction_summary": {
                    "outbound_bytes": 1200,
                    "inbound_bytes": 6400,
                    "unknown_bytes": 12,
                    "outbound_packets": 20,
                    "inbound_packets": 40,
                    "unknown_packets": 1,
                },
                "flow_summary": {
                    "flow_count": 15,
                    "tcp_stream_count": 11,
                    "udp_flow_count": 4,
                },
                "burst_summary": {
                    "active_second_count": 32,
                    "burst_count": 7,
                    "max_burst_duration_s": 8.0,
                    "median_burst_duration_s": 2.0,
                    "median_interburst_gap_s": 3.0,
                },
                "tls_quic_visibility": {
                    "tls_visible": True,
                    "tls_handshake_packets": 21,
                    "tls_client_hello_packets": 10,
                    "tls_server_hello_packets": 9,
                    "tls_sni_unique_count": 6,
                    "tls_alpn_unique_count": 2,
                    "quic_candidate_packets": 5,
                },
                "transport_health": {
                    "issue_packet_count": 4,
                    "reset_packet_count": 2,
                    "lifecycle_summary": {
                        "stream_count": 11,
                        "handshake_seen_stream_count": 9,
                        "issue_stream_count": 3,
                        "reset_stream_count": 2,
                        "clean_close_stream_count": 6,
                        "partial_stream_count": 3,
                    },
                },
                "tls_fingerprints": {
                    "client_hello_count": 12,
                    "server_hello_count": 11,
                    "unique_ja3_count": 3,
                    "unique_ja4_count": 2,
                    "unique_ja3s_count": 2,
                    "top1_ja3_share": 0.5,
                    "top1_ja4_share": 0.75,
                    "top1_ja3s_share": 0.6,
                },
            }
        ),
        encoding="utf-8",
    )

    row = index_from_evidence.build_dynamic_network_features_row_from_evidence_pack(run_dir)

    assert row is not None
    assert row["direction_outbound_bytes"] == 1200
    assert row["direction_inbound_packets"] == 40
    assert row["flow_count"] == 15
    assert row["tcp_stream_count"] == 11
    assert row["udp_flow_count"] == 4
    assert row["active_second_count"] == 32
    assert row["burst_count"] == 7
    assert row["max_burst_duration_s"] == 8.0
    assert row["median_interburst_gap_s"] == 3.0
    assert row["outbound_packet_ratio"] == 20.0 / 61.0
    assert row["inbound_packet_ratio"] == 40.0 / 61.0
    assert row["outbound_byte_ratio"] == 1200.0 / 7612.0
    assert row["inbound_byte_ratio"] == 6400.0 / 7612.0
    assert row["direction_confident_packet_ratio"] is None
    assert row["active_second_ratio"] == 32.0 / 240.0
    assert row["bursts_per_min"] == 7.0 / 4.0
    assert row["median_packets_per_flow"] is None
    assert row["median_bytes_per_flow"] is None
    assert row["top_flow_packet_share"] is None
    assert row["top_flow_byte_share"] is None
    assert row["tls_handshakes_per_min"] == 21.0 / 4.0
    assert row["tls_visible"] == 1
    assert row["tls_handshake_packets"] == 21
    assert row["tls_sni_unique_count"] == 6
    assert row["quic_candidate_packets"] == 5
    assert row["tcp_issue_packet_count"] == 4
    assert row["tcp_reset_packet_count"] == 2
    assert row["tcp_stream_count_lifecycle"] == 11
    assert row["tcp_handshake_seen_stream_count"] == 9
    assert row["tcp_issue_stream_count"] == 3
    assert row["tcp_reset_stream_count"] == 2
    assert row["tcp_clean_close_stream_count"] == 6
    assert row["tcp_partial_stream_count"] == 3
    assert row["tls_client_hello_count"] == 12
    assert row["tls_server_hello_count"] == 11
    assert row["unique_ja3_count"] == 3
    assert row["unique_ja4_count"] == 2
    assert row["unique_ja3s_count"] == 2
    assert row["top1_ja3_share"] == 0.5


def test_build_dynamic_network_features_row_backfills_transport_lifecycle_from_pcap(monkeypatch, tmp_path):
    from scytaledroid.DynamicAnalysis.storage import index_from_evidence

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run130"
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True)
    (run_dir / "artifacts" / "pcapdroid_capture" / "sample.pcap").write_bytes(b"pcap")
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run130",
                "status": "success",
                "target": {"package_name": "com.example.transport"},
                "dataset": {
                    "tier": "dataset",
                    "countable": True,
                    "valid_dataset_run": True,
                },
                "operator": {
                    "run_profile": "interaction_manual",
                    "interaction_level": "manual",
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {"capture_duration_s": 240.0},
                "proxies": {},
                "quality": {"protocol": {}},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "pcap_path": "artifacts/pcapdroid_capture/sample.pcap",
                "direction_summary": {},
                "flow_summary": {},
                "burst_summary": {},
                "tls_quic_visibility": {},
                "transport_health": {},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.storage.index_from_evidence.summarize_transport_health",
        lambda *args, **kwargs: {
            "issue_packet_count": 5,
            "reset_packet_count": 1,
            "lifecycle_summary": {
                "stream_count": 4,
                "handshake_seen_stream_count": 3,
                "issue_stream_count": 2,
                "reset_stream_count": 1,
                "clean_close_stream_count": 2,
                "partial_stream_count": 1,
                "issue_stream_ratio": 0.5,
                "reset_stream_ratio": 0.25,
                "clean_close_stream_ratio": 0.5,
                "partial_stream_ratio": 0.25,
            },
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.storage.index_from_evidence.summarize_tls_fingerprints",
        lambda *args, **kwargs: {
            "client_hello_count": 4,
            "server_hello_count": 3,
            "unique_ja3_count": 2,
            "unique_ja4_count": 2,
            "unique_ja3s_count": 1,
            "top1_ja3_share": 0.75,
            "top1_ja4_share": 0.75,
            "top1_ja3s_share": 1.0,
        },
    )

    row = index_from_evidence.build_dynamic_network_features_row_from_evidence_pack(run_dir)

    assert row is not None
    assert row["tcp_issue_packet_count"] == 5
    assert row["tcp_reset_packet_count"] == 1
    assert row["tcp_stream_count_lifecycle"] == 4
    assert row["tcp_handshake_seen_stream_count"] == 3
    assert row["tcp_issue_stream_count"] == 2
    assert row["tcp_reset_stream_count"] == 1
    assert row["tcp_clean_close_stream_count"] == 2
    assert row["tcp_partial_stream_count"] == 1
    assert row["tcp_issue_stream_ratio"] == 0.5
    assert row["tcp_reset_stream_ratio"] == 0.25
    assert row["tcp_clean_close_stream_ratio"] == 0.5
    assert row["tcp_partial_stream_ratio"] == 0.25
    assert row["tls_client_hello_count"] == 4
    assert row["tls_server_hello_count"] == 3
    assert row["unique_ja3_count"] == 2
    assert row["unique_ja4_count"] == 2
    assert row["unique_ja3s_count"] == 1
    assert row["top1_ja3_share"] == 0.75


def test_build_dynamic_network_features_row_uses_pcap_features_summaries_when_report_blocks_missing(tmp_path):
    from scytaledroid.DynamicAnalysis.storage import index_from_evidence

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run131"
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run131",
                "status": "success",
                "target": {"package_name": "com.example.modern"},
                "dataset": {
                    "tier": "dataset",
                    "countable": True,
                    "valid_dataset_run": True,
                },
                "operator": {
                    "run_profile": "interaction_manual",
                    "interaction_level": "manual",
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {"capture_duration_s": 240.0},
                "proxies": {},
                "quality": {"protocol": {}},
                "visibility": {
                    "status": "ok",
                    "summary": {
                        "tls_visible": True,
                        "tls_handshake_packets": 8,
                        "tls_client_hello_packets": 4,
                        "tls_server_hello_packets": 4,
                        "tls_sni_unique_count": 2,
                        "tls_alpn_unique_count": 1,
                        "quic_candidate_packets": 0,
                    },
                },
                "transport_health": {
                    "status": "ok",
                    "summary": {
                        "issue_packet_count": 1,
                        "reset_packet_count": 0,
                        "lifecycle_summary": {
                            "stream_count": 2,
                            "handshake_seen_stream_count": 2,
                            "issue_stream_count": 1,
                            "reset_stream_count": 0,
                            "clean_close_stream_count": 1,
                            "partial_stream_count": 1,
                            "issue_stream_ratio": 0.5,
                            "reset_stream_ratio": 0.0,
                            "clean_close_stream_ratio": 0.5,
                            "partial_stream_ratio": 0.5,
                        },
                    },
                },
                "fingerprints": {
                    "status": "ok",
                    "summary": {
                        "client_hello_count": 4,
                        "server_hello_count": 4,
                        "unique_ja3_count": 2,
                        "unique_ja4_count": 2,
                        "unique_ja3s_count": 1,
                        "top1_ja3_share": 0.75,
                        "top1_ja4_share": 0.75,
                        "top1_ja3s_share": 1.0,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "direction_summary": {},
                "flow_summary": {},
                "burst_summary": {},
                "tls_quic_visibility": {},
                "transport_health": {},
            }
        ),
        encoding="utf-8",
    )

    row = index_from_evidence.build_dynamic_network_features_row_from_evidence_pack(run_dir)

    assert row is not None
    assert row["tls_visible"] == 1
    assert row["tls_handshake_packets"] == 8
    assert row["tls_client_hello_packets"] == 4
    assert row["tls_server_hello_packets"] == 4
    assert row["tls_sni_unique_count"] == 2
    assert row["tls_alpn_unique_count"] == 1
    assert row["tcp_issue_packet_count"] == 1
    assert row["tcp_stream_count_lifecycle"] == 2
    assert row["tcp_issue_stream_ratio"] == 0.5
    assert row["unique_ja3_count"] == 2
    assert row["unique_ja4_count"] == 2
    assert row["unique_ja3s_count"] == 1
    assert row["top1_ja4_share"] == 0.75
