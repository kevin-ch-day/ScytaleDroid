from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap import dataset_tracker


def test_peek_next_run_protocol_baseline_until_first_valid(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))

    # No tracker file yet: first run should be baseline.
    proto = dataset_tracker.peek_next_run_protocol("com.example.app", tier="dataset")
    assert proto
    assert proto["run_profile"] == "baseline_idle"
    assert proto["run_sequence"] == 1

    # Simulate one invalid attempt: still baseline until first valid run exists.
    tracker = {
        "apps": {
            "com.example.app": {
                "runs": [{"run_id": "r1", "valid_dataset_run": False}],
                "valid_runs": 0,
            }
        }
    }
    (tmp_path / "archive").mkdir(parents=True, exist_ok=True)
    (tmp_path / "archive" / "dataset_plan.json").write_text(json.dumps(tracker), encoding="utf-8")
    proto = dataset_tracker.peek_next_run_protocol("com.example.app", tier="dataset")
    assert proto
    assert proto["run_profile"] == "baseline_idle"
    assert proto["run_sequence"] == 2

    # Once a valid run exists: next runs should switch to interactive profile.
    tracker["apps"]["com.example.app"]["runs"].append({"run_id": "r2", "valid_dataset_run": True})
    tracker["apps"]["com.example.app"]["valid_runs"] = 1
    (tmp_path / "archive" / "dataset_plan.json").write_text(json.dumps(tracker), encoding="utf-8")
    proto = dataset_tracker.peek_next_run_protocol("com.example.app", tier="dataset")
    assert proto
    assert proto["run_profile"] == "interactive_use"
    assert proto["run_sequence"] == 3


def test_update_dataset_tracker_records_run_protocol(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_MIN_DURATION_S", 120)

    run_dir = tmp_path / "run"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {"parsed": {"capture_duration_s": 180, "packet_count": 1000, "data_size_bytes": 123}},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(json.dumps({}), encoding="utf-8")
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps(
            {
                "telemetry": {
                    "stats": {
                        "sampling_duration_seconds": 180,
                        "netstats_bytes_in_total": 1,
                        "netstats_bytes_out_total": 1,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-123",
        created_at="2026-02-07T00:00:00Z",
        status="success",
        target={"package_name": "com.example.app"},
        scenario={"id": "basic_usage"},
        operator={
            "tier": "dataset",
            "run_profile": "baseline_idle",
            "run_sequence": 1,
            "interaction_level": "minimal",
        },
    )
    manifest.add_artifacts(
        [
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/test.pcap",
                type="pcapdroid_capture",
                sha256="0" * 64,
                size_bytes=int(dataset_tracker.MIN_PCAP_BYTES) + 1,
                produced_by="pcapdroid_capture",
                origin="host",
                pull_status="ok",
            )
        ]
    )
    manifest.finalize()

    out_path = dataset_tracker.update_dataset_tracker(manifest, run_dir)
    assert out_path and out_path.exists()
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    run = payload["apps"]["com.example.app"]["runs"][0]
    assert run["run_profile"] == "baseline_idle"
    assert run["run_sequence"] == 1
    assert run["interaction_level"] == "minimal"


def test_dataset_validity_rejects_short_pcap_span_when_netstats_large(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_MIN_DURATION_S", 120)

    run_dir = tmp_path / "run"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "pcap_features.json").write_text(json.dumps({}), encoding="utf-8")
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {"parsed": {"capture_duration_s": 4.0, "packet_count": 2000, "data_size_bytes": 10}},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps(
            {
                "telemetry": {
                    "stats": {
                        "sampling_duration_seconds": 180,
                        "netstats_bytes_in_total": 100 * 1024 * 1024,
                        "netstats_bytes_out_total": 1,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-xyz",
        created_at="2026-02-07T00:00:00Z",
        status="success",
        target={"package_name": "com.example.app"},
        scenario={"id": "basic_usage"},
        operator={"tier": "dataset", "run_profile": "interactive_use", "run_sequence": 2},
    )
    manifest.add_artifacts(
        [
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/test.pcap",
                type="pcapdroid_capture",
                sha256="0" * 64,
                size_bytes=int(dataset_tracker.MIN_PCAP_BYTES) + 1,
                produced_by="pcapdroid_capture",
                origin="host",
                pull_status="ok",
            )
        ]
    )
    manifest.finalize()

    out_path = dataset_tracker.update_dataset_tracker(manifest, run_dir)
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    run = payload["apps"]["com.example.app"]["runs"][0]
    assert run["valid_dataset_run"] is False
