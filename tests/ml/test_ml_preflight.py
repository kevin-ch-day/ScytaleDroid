from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.preflight import compute_ml_preflight, load_run_inputs


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_ml_preflight_reports_missing_frozen_inputs(tmp_path: Path):
    run_dir = tmp_path / "run-1"
    run_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "dynamic_run_id": "run-1",
        "target": {"package_name": "com.example.app"},
        "operator": {"tier": "dataset", "dataset_validity": {"valid_dataset_run": True}},
        "artifacts": [],
    }
    _write_json(run_dir / "run_manifest.json", manifest)
    # Only write summary; omit pcap_report and plan and pcap_features.
    _write_json(run_dir / "analysis" / "summary.json", {"telemetry": {"stats": {"sampling_duration_seconds": 42}}})

    inputs = load_run_inputs(run_dir)
    assert inputs is not None
    result = compute_ml_preflight(inputs)

    assert result.frozen_inputs_ok is False
    assert "inputs/static_dynamic_plan.json" in result.missing_inputs
    assert "analysis/pcap_report.json" in result.missing_inputs
    assert result.skip_reason == "ML_SKIPPED_MISSING_PROTOCOL_FEATURES"


def test_ml_preflight_computes_expected_windows(tmp_path: Path):
    run_dir = tmp_path / "run-2"
    run_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "dynamic_run_id": "run-2",
        "target": {"package_name": "com.example.app"},
        "operator": {"tier": "dataset", "dataset_validity": {"valid_dataset_run": True}},
        "artifacts": [{"type": "pcapdroid_capture", "relative_path": "artifacts/pcap.pcap"}],
    }
    _write_json(run_dir / "run_manifest.json", manifest)
    _write_json(run_dir / "inputs" / "static_dynamic_plan.json", {"run_identity": {}})
    _write_json(run_dir / "analysis" / "summary.json", {"telemetry": {"stats": {"sampling_duration_seconds": 23}}})
    _write_json(run_dir / "analysis" / "pcap_report.json", {"report_status": "ok"})
    _write_json(run_dir / "analysis" / "pcap_features.json", {"metrics": {}, "proxies": {}, "quality": {}})
    (run_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "pcap.pcap").write_bytes(b"\x00\x01")

    inputs = load_run_inputs(run_dir)
    assert inputs is not None
    result = compute_ml_preflight(inputs)

    # For duration 23s and window=10/stride=5, expect 3 full windows and 2 dropped.
    assert result.windows_total_expected == 3
    assert result.dropped_partial_windows_expected == 2

