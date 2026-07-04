from __future__ import annotations

from tests.dynamic._index_from_evidence_support import write_json


def test_build_dynamic_session_row_from_evidence_pack(tmp_path):
    from scytaledroid.DynamicAnalysis.storage.index_from_evidence import (
        build_dynamic_session_row_from_evidence_pack,
    )

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run123"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)

    write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run123",
            "started_at": "2026-02-07T00:00:00Z",
            "ended_at": "2026-02-07T00:03:00Z",
            "status": "success",
            "target": {"package_name": "com.example.app"},
            "dataset": {"tier": "dataset", "duration_seconds": 180, "pcap_size_bytes": 1234},
            "operator": {"run_profile": "baseline_idle", "sampling_rate_s": 2},
            "artifacts": [{"type": "pcapdroid_capture", "relative_path": "inputs/app_only.pcapng"}],
        },
    )
    write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "static_run_id": 99,
            "package_name": "com.example.app",
            "version_code": 1,
            "version_name": "1.0",
            "run_identity": {"run_signature": "x", "run_signature_version": "v1"},
        },
    )
    write_json(
        run_dir / "analysis" / "summary.json",
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
        },
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
    write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run124",
            "status": "success",
            "target": {"package_name": "com.example.app"},
            "dataset": {"tier": "dataset", "duration_seconds": 60, "pcap_size_bytes": 10},
            "operator": {"sampling_rate_s": 1},
        },
    )
    write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "static_run_id": 100,
            "package_name": "com.example.app",
            "run_identity": {
                "run_signature": "x",
                "run_signature_version": "v1",
                "static_handoff_hash": "a" * 64,
            },
        },
    )
    write_json(
        run_dir / "analysis" / "summary.json",
        {"dynamic_run_id": "run124", "telemetry": {"stats": {}, "quality": {}}},
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
    write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run125",
            "status": "success",
            "target": {"package_name": "com.example.legacy"},
            "dataset": {"tier": "dataset", "duration_seconds": 60},
            "operator": {"sampling_rate_s": 1},
        },
    )
    write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "package_name": "com.example.legacy",
            "run_identity": {
                "static_run_id": 321,
                "run_signature": "legacy-sig",
                "run_signature_version": "v1",
            },
        },
    )
    write_json(
        run_dir / "analysis" / "summary.json",
        {"dynamic_run_id": "run125", "telemetry": {"stats": {}, "quality": {}}},
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
    write_json(
        run_dir / "run_manifest.json",
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
        },
    )
    write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {"package_name": "com.example.current"},
    )
    write_json(
        run_dir / "analysis" / "summary.json",
        {"dynamic_run_id": "run126", "telemetry": {"stats": {}, "quality": {}}},
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
    write_json(
        run_dir / "run_manifest.json",
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
        },
    )
    write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {"package_name": "com.example.current"},
    )
    write_json(
        run_dir / "analysis" / "summary.json",
        {"dynamic_run_id": "run126b", "telemetry": {"stats": {}, "quality": {}}},
    )

    row = index_from_evidence.build_dynamic_session_row_from_evidence_pack(run_dir)

    assert row is not None
    assert row["countable"] == 0
    assert row["valid_dataset_run"] == 1
    assert row["invalid_reason_code"] == "EXCLUDED_SCRIPT_ABORT"
