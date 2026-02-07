from __future__ import annotations

import json
from pathlib import Path


def test_build_dynamic_session_row_from_evidence_pack(tmp_path):
    from scytaledroid.DynamicAnalysis.storage.index_from_evidence import build_dynamic_session_row_from_evidence_pack

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
                "operator": {"run_profile": "baseline_idle"},
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

    row = build_dynamic_session_row_from_evidence_pack(run_dir)
    assert row is not None
    assert row["dynamic_run_id"] == "run123"
    assert row["package_name"] == "com.example.app"
    assert row["static_run_id"] == 99
    assert row["pcap_bytes"] == 1234

