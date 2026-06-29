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
