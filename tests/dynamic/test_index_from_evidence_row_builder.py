from __future__ import annotations

from tests.dynamic._index_from_evidence_support import write_json


def test_index_from_evidence_smoke_session_and_network_rows(tmp_path):
    from scytaledroid.DynamicAnalysis.storage import index_from_evidence

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-smoke"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)
    write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run-smoke",
            "status": "success",
            "target": {"package_name": "com.example.smoke"},
            "dataset": {
                "tier": "dataset",
                "countable": True,
                "valid_dataset_run": True,
                "pcap_size_bytes": 100,
            },
            "operator": {"sampling_rate_s": 1},
        },
    )
    write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {"package_name": "com.example.smoke", "static_run_id": 1},
    )
    write_json(
        run_dir / "analysis" / "summary.json",
        {"dynamic_run_id": "run-smoke", "telemetry": {"stats": {}, "quality": {}}},
    )
    write_json(
        run_dir / "analysis" / "pcap_features.json",
        {"metrics": {}, "proxies": {}, "quality": {"protocol": {}}},
    )
    write_json(run_dir / "analysis" / "pcap_report.json", {})

    session_row = index_from_evidence.build_dynamic_session_row_from_evidence_pack(run_dir)
    network_row = index_from_evidence.build_dynamic_network_features_row_from_evidence_pack(run_dir)

    assert session_row is not None
    assert network_row is not None
    assert session_row["dynamic_run_id"] == "run-smoke"
    assert network_row["dynamic_run_id"] == "run-smoke"
