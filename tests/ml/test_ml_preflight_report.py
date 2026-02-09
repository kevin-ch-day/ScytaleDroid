from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight_report import write_ml_preflight_report


def test_write_ml_preflight_report_writes_csv(tmp_path, monkeypatch):
    # Arrange fake OUTPUT_DIR and DATA_DIR
    out_dir = tmp_path / "out"
    data_dir = tmp_path / "data"
    (out_dir / "evidence" / "dynamic" / "run-1").mkdir(parents=True, exist_ok=True)
    (data_dir / "archive" / "ml").mkdir(parents=True, exist_ok=True)

    import scytaledroid.Config.app_config as app_config

    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(out_dir))
    monkeypatch.setattr(app_config, "DATA_DIR", str(data_dir))

    run_dir = out_dir / "evidence" / "dynamic" / "run-1"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)

    manifest = {
        "dynamic_run_id": "run-1",
        "target": {"package_name": "com.example.app"},
        "operator": {"tier": "dataset"},
        "dataset": {"tier": "dataset", "valid_dataset_run": True},
        "artifacts": [{"type": "pcapdroid_capture", "relative_path": "artifacts/pcap.pcap"}],
    }
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps({"telemetry": {"stats": {"sampling_duration_seconds": 23}}}),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(json.dumps({"report_status": "ok"}), encoding="utf-8")
    (run_dir / "analysis" / "pcap_features.json").write_text(json.dumps({}), encoding="utf-8")
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(json.dumps({}), encoding="utf-8")
    (run_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "pcap.pcap").write_bytes(b"\x00\x01")

    # Act
    path = write_ml_preflight_report()

    # Assert
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "run_id" in text
    assert "run-1" in text
