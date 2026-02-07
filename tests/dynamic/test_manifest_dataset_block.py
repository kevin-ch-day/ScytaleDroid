import json

from scytaledroid.DynamicAnalysis.core.manifest import RunManifest, manifest_to_dict


def test_manifest_includes_dataset_block() -> None:
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-123",
        created_at="2026-02-07T00:00:00Z",
        status="success",
        dataset={"tier": "dataset", "valid_dataset_run": True, "invalid_reason_code": None},
    )
    payload = manifest_to_dict(manifest)
    assert "dataset" in payload
    assert isinstance(payload["dataset"], dict)
    assert payload["dataset"]["tier"] == "dataset"
    assert payload["dataset"]["valid_dataset_run"] is True


def test_ml_preflight_accepts_dataset_block(tmp_path) -> None:
    # Minimal evidence-pack-like structure for preflight checks.
    run_dir = tmp_path / "run"
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "analysis").mkdir(parents=True)

    (run_dir / "inputs" / "static_dynamic_plan.json").write_text("{}", encoding="utf-8")
    (run_dir / "analysis" / "summary.json").write_text(json.dumps({"telemetry": {"stats": {"sampling_duration_seconds": 120}}}), encoding="utf-8")
    (run_dir / "analysis" / "pcap_report.json").write_text("{}", encoding="utf-8")
    (run_dir / "analysis" / "pcap_features.json").write_text("{}", encoding="utf-8")
    # Pretend we have a PCAP referenced via artifacts list.
    (run_dir / "artifacts").mkdir(parents=True)
    (run_dir / "artifacts" / "capture.pcap").write_bytes(b"\x00" * 10)

    manifest = {
        "run_manifest_version": 1,
        "dynamic_run_id": "run-123",
        "created_at": "2026-02-07T00:00:00Z",
        "status": "success",
        "dataset": {"tier": "dataset", "valid_dataset_run": True},
        "artifacts": [{"relative_path": "artifacts/capture.pcap", "type": "pcapdroid_capture"}],
        "target": {"package_name": "com.example.app"},
    }
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    from scytaledroid.DynamicAnalysis.ml.preflight import load_run_inputs, is_valid_dataset_run

    inputs = load_run_inputs(run_dir)
    assert inputs is not None
    assert is_valid_dataset_run(inputs) is True

