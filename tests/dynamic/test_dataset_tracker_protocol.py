from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap import dataset_tracker


def test_peek_next_run_protocol_baseline_until_first_valid(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_DATASET_BASELINE_RUNS", 1)
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_DATASET_INTERACTIVE_RUNS", 2)

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
    # Sequence is quota slot index (valid runs + 1), not raw attempt count.
    assert proto["run_sequence"] == 1

    # Once a valid run exists: next runs should switch to interactive profile.
    tracker["apps"]["com.example.app"]["runs"].append(
        {"run_id": "r2", "valid_dataset_run": True, "run_profile": "baseline_idle"}
    )
    tracker["apps"]["com.example.app"]["valid_runs"] = 1
    (tmp_path / "archive" / "dataset_plan.json").write_text(json.dumps(tracker), encoding="utf-8")
    proto = dataset_tracker.peek_next_run_protocol("com.example.app", tier="dataset")
    assert proto
    assert proto["run_profile"] == "interaction_scripted"
    assert proto["run_sequence"] == 2


def test_peek_next_run_protocol_two_baselines_when_baseline_required_is_two(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_DATASET_BASELINE_RUNS", 2)
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_DATASET_INTERACTIVE_RUNS", 2)

    proto = dataset_tracker.peek_next_run_protocol("com.example.app", tier="dataset")
    assert proto
    assert proto["run_profile"] == "baseline_idle"
    assert proto["run_sequence"] == 1

    tracker = {
        "apps": {
            "com.example.app": {
                "runs": [{"run_id": "r1", "valid_dataset_run": True, "run_profile": "baseline_idle"}],
                "valid_runs": 1,
            }
        }
    }
    (tmp_path / "archive").mkdir(parents=True, exist_ok=True)
    (tmp_path / "archive" / "dataset_plan.json").write_text(json.dumps(tracker), encoding="utf-8")
    proto = dataset_tracker.peek_next_run_protocol("com.example.app", tier="dataset")
    assert proto
    # Second valid slot still baseline when protocol is 4 runs per app.
    assert proto["run_profile"] == "baseline_idle"
    assert proto["run_sequence"] == 2

    tracker["apps"]["com.example.app"]["runs"].append(
        {"run_id": "r2", "valid_dataset_run": True, "run_profile": "baseline_idle"}
    )
    tracker["apps"]["com.example.app"]["valid_runs"] = 2
    (tmp_path / "archive" / "dataset_plan.json").write_text(json.dumps(tracker), encoding="utf-8")
    proto = dataset_tracker.peek_next_run_protocol("com.example.app", tier="dataset")
    assert proto
    assert proto["run_profile"] == "interaction_scripted"
    assert proto["run_sequence"] == 3


def test_update_dataset_tracker_records_run_protocol(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_MIN_DURATION_S", 120)
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_DATASET_BASELINE_RUNS", 1)
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_DATASET_INTERACTIVE_RUNS", 2)

    run_dir = tmp_path / "run"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "missing_tools": [],
                "capinfos": {"parsed": {"capture_duration_s": 180, "packet_count": 1000, "data_size_bytes": 123}},
                "protocol_hierarchy": [{"protocol": "quic", "frames": 1, "bytes": 1}],
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


def test_dataset_validity_prefers_pcap_capture_span_for_sampling_gate(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_MIN_DURATION_S", 120)

    run_dir = tmp_path / "run"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "pcap_features.json").write_text(json.dumps({}), encoding="utf-8")
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "missing_tools": [],
                "capinfos": {"parsed": {"capture_duration_s": 4.0, "packet_count": 2000, "data_size_bytes": 10}},
                "protocol_hierarchy": [{"protocol": "tcp", "frames": 1, "bytes": 1}],
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
        operator={
            "tier": "dataset",
            "run_profile": "interactive_use",
            "run_sequence": 2,
            "interaction_level": "interactive",
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
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    run = payload["apps"]["com.example.app"]["runs"][0]
    assert run["valid_dataset_run"] is False
    assert run["invalid_reason_code"] == "INSUFFICIENT_DURATION"
    assert run["actual_sampling_seconds"] == 4.0
    assert run["actual_sampling_seconds_source"] == "capinfos_capture_duration_s"


def test_dataset_validity_enforces_paper_min_sampling_floor(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_MIN_DURATION_S", 30)

    run_dir = tmp_path / "run-low-window"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "pcap_features.json").write_text(json.dumps({}), encoding="utf-8")
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "missing_tools": [],
                "capinfos": {"parsed": {"capture_duration_s": 90, "packet_count": 1000, "data_size_bytes": 10}},
                "protocol_hierarchy": [{"protocol": "tcp", "frames": 1, "bytes": 1}],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps({"telemetry": {"stats": {"sampling_duration_seconds": 90}}}),
        encoding="utf-8",
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-low-window",
        created_at="2026-02-07T00:00:00Z",
        status="success",
        target={"package_name": "com.example.app"},
        scenario={"id": "basic_usage"},
        operator={
            "tier": "dataset",
            "run_profile": "interaction_scripted",
            "run_sequence": 2,
            "interaction_level": "scripted",
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
    assert run["valid_dataset_run"] is False
    assert run["invalid_reason_code"] == "INSUFFICIENT_DURATION"
    # Paper-mode sampling floor is hard-locked to >=180s; this fails before
    # window-count-specific gating.
    assert run.get("window_count_too_low") in (None, 0)


def test_dataset_validity_persists_window_count_recompute_audit(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_MIN_DURATION_S", 120)

    run_dir = tmp_path / "run-recompute"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "pcap_features.json").write_text(json.dumps({}), encoding="utf-8")
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "missing_tools": [],
                "capinfos": {"parsed": {"capture_duration_s": 205, "packet_count": 1000, "data_size_bytes": 10}},
                "protocol_hierarchy": [{"protocol": "tcp", "frames": 1, "bytes": 1}],
            }
        ),
        encoding="utf-8",
    )
    # No sampling_duration_seconds in telemetry -> forces recompute path.
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps({"telemetry": {"stats": {}}}),
        encoding="utf-8",
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-recompute",
        created_at="2026-02-07T00:00:00Z",
        status="success",
        target={"package_name": "com.example.app"},
        scenario={"id": "basic_usage"},
        operator={
            "tier": "dataset",
            "run_profile": "interaction_scripted",
            "run_sequence": 2,
            "interaction_level": "scripted",
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
    assert run["valid_dataset_run"] is True
    assert run["window_count"] >= int(dataset_tracker.MIN_WINDOWS_PER_RUN)
    assert run["window_count_original"] == run["window_count_final"]
    assert run["window_count"] == run["window_count_final"]
    assert run["window_count_source"] == "recompute_capinfos_capture_duration_s"
    audit_path = run_dir / "analysis" / "recompute_attempt.jsonl"
    assert audit_path.exists()
    lines = [line for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 1
    record = json.loads(lines[0])
    assert record["trigger_condition"] == "WINDOW_COUNT_MISSING"


def test_dataset_validity_short_run_tolerates_one_second_capture_jitter(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_MIN_DURATION_S", 120)

    run_dir = tmp_path / "run-jitter"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "pcap_features.json").write_text(json.dumps({}), encoding="utf-8")
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "missing_tools": [],
                "capinfos": {"parsed": {"capture_duration_s": 239, "packet_count": 1000, "data_size_bytes": 10}},
                "protocol_hierarchy": [{"protocol": "tcp", "frames": 1, "bytes": 1}],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps({"telemetry": {"stats": {"sampling_duration_seconds": 240}}}),
        encoding="utf-8",
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-jitter",
        created_at="2026-02-07T00:00:00Z",
        status="success",
        target={"package_name": "com.example.app"},
        scenario={"id": "basic_usage"},
        operator={
            "tier": "dataset",
            "run_profile": "interaction_scripted",
            "run_sequence": 2,
            "interaction_level": "scripted",
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
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    run = payload["apps"]["com.example.app"]["runs"][0]
    assert run["valid_dataset_run"] is True
    assert run.get("short_run", 0) == 0
    assert run["actual_sampling_seconds"] == 239.0
    assert run["actual_sampling_seconds_source"] == "capinfos_capture_duration_s"


def test_normalize_quota_marking_skips_paper_ineligible_runs(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dataset_tracker.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_DATASET_BASELINE_RUNS", 1)
    monkeypatch.setattr(dataset_tracker.app_config, "DYNAMIC_DATASET_INTERACTIVE_RUNS", 2)

    tracker = {
        "apps": {
            "com.example.app": {
                "runs": [
                    {
                        "run_id": "r1",
                        "ended_at": "2026-02-22T10:00:00+00:00",
                        "run_profile": "baseline_idle",
                        "valid_dataset_run": True,
                        "paper_eligible": False,
                    },
                    {
                        "run_id": "r2",
                        "ended_at": "2026-02-22T10:05:00+00:00",
                        "run_profile": "baseline_idle",
                        "valid_dataset_run": True,
                        "paper_eligible": True,
                    },
                    {
                        "run_id": "r3",
                        "ended_at": "2026-02-22T10:10:00+00:00",
                        "run_profile": "interaction_scripted",
                        "valid_dataset_run": True,
                        "paper_eligible": False,
                    },
                    {
                        "run_id": "r4",
                        "ended_at": "2026-02-22T10:15:00+00:00",
                        "run_profile": "interaction_scripted",
                        "valid_dataset_run": True,
                        "paper_eligible": True,
                    },
                    {
                        "run_id": "r5",
                        "ended_at": "2026-02-22T10:20:00+00:00",
                        "run_profile": "interaction_scripted",
                        "valid_dataset_run": True,
                        "paper_eligible": True,
                    },
                ]
            }
        }
    }
    (tmp_path / "archive").mkdir(parents=True, exist_ok=True)
    (tmp_path / "archive" / "dataset_plan.json").write_text(json.dumps(tracker), encoding="utf-8")

    normalized = dataset_tracker.load_dataset_tracker()
    app = normalized["apps"]["com.example.app"]
    assert app["valid_runs"] == 3
    assert app["baseline_valid_runs"] == 1
    assert app["interactive_valid_runs"] == 2
    assert app["quota_met"] is True

    runs = {r["run_id"]: r for r in app["runs"]}
    assert runs["r1"]["counts_toward_quota"] is False
    assert runs["r2"]["counts_toward_quota"] is True
    assert runs["r3"]["counts_toward_quota"] is False
    assert runs["r4"]["counts_toward_quota"] is True
    assert runs["r5"]["counts_toward_quota"] is True
