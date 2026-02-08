from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, ObserverRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap import dataset_tracker


def test_dataset_validity_prefers_pcap_too_small_over_capture_interrupted(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_MIN_DURATION_S", 120)
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_MIN_PCAP_BYTES", 100_000)

    run_dir = tmp_path / "run"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "pcap_features.json").write_text(json.dumps({}), encoding="utf-8")
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "missing_tools": [],
                "capinfos": {"parsed": {"capture_duration_s": 180, "packet_count": 1000, "data_size_bytes": 10}},
                "protocol_hierarchy": [{"protocol": "tcp", "frames": 1, "bytes": 1}],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps({"telemetry": {"stats": {"sampling_duration_seconds": 180}}}),
        encoding="utf-8",
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-small",
        created_at="2026-02-07T00:00:00Z",
        status="degraded",
        target={"package_name": "com.example.app"},
        scenario={"id": "basic_usage"},
        operator={
            "tier": "dataset",
            "run_profile": "baseline_idle",
            "run_sequence": 1,
            "interaction_level": "minimal",
        },
    )
    manifest.observers = [
        ObserverRecord(
            observer_id="pcapdroid_capture",
            status="failed",
            error="pcap too small",
        )
    ]
    manifest.add_artifacts(
        [
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/test.pcap",
                type="pcapdroid_capture",
                sha256="0" * 64,
                size_bytes=7_283,
                produced_by="pcapdroid_capture",
                origin="host",
                pull_status="failed",
            )
        ]
    )
    manifest.finalize()

    out_path = dataset_tracker.update_dataset_tracker(manifest, run_dir)
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    run = payload["apps"]["com.example.app"]["runs"][0]
    assert run["valid_dataset_run"] is False
    assert run["invalid_reason_code"] == "PCAP_TOO_SMALL"
