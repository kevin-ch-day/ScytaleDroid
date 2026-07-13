from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as config
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import RunInputs
from scytaledroid.DynamicAnalysis.ml.freeze_profile.run_artifacts import (
    read_ml_config_fingerprint,
    write_cohort_status,
    write_model_manifest,
)
from scytaledroid.DynamicAnalysis.ml.telemetry_windowing import WindowSpec


def _run_inputs(tmp_path: Path) -> RunInputs:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    return RunInputs(
        run_id="run-1",
        run_dir=run_dir,
        manifest={
            "environment": {"python_version": "3.x"},
            "artifacts": [{"type": "pcapdroid_capture_meta", "relative_path": "meta.json"}],
            "target": {"identity_checked_at_start_utc": "2026-07-01T00:00:00Z"},
        },
        plan={
            "package_name": "com.example.app",
            "version_code": "1",
            "plan_schema_version": "test",
            "run_identity": {
                "package_name_lc": "com.example.app",
                "version_code": "1",
                "base_apk_sha256": "a" * 64,
                "artifact_set_hash": "b" * 64,
                "signer_set_hash": "c" * 64,
                "static_handoff_hash": "d" * 64,
            },
        },
        summary={},
        pcap_report={"capinfos": {"parsed": {"file_type": "pcapng"}}},
        pcap_features={"feature_schema_version": "test"},
        pcap_path=None,
        identity_key="com.example.app:1",
        package_name="com.example.app",
        run_profile="baseline",
    )


def test_write_model_manifest_preserves_method_basis_and_config_sidecar(tmp_path: Path) -> None:
    run_inputs = _run_inputs(tmp_path)
    (run_inputs.run_dir / "meta.json").write_text(
        json.dumps({"capture_mode": "vpn", "pcapdroid_package": "com.emanuelef.remote_capture", "pcapdroid_version": "1.2.3"}),
        encoding="utf-8",
    )
    out_dir = run_inputs.run_dir / "analysis" / "ml" / config.ML_SCHEMA_LABEL
    out_dir.mkdir(parents=True)
    path = out_dir / "model_manifest.json"

    write_model_manifest(
        path,
        run_inputs=run_inputs,
        identity_key_used="base_apk_sha256:" + "a" * 64,
        seed=7,
        window_spec=WindowSpec(window_size_s=10.0, stride_s=5.0),
        model_outputs={config.MODEL_IFOREST: {"params": {}}},
        freeze_manifest_path=None,
        ml_config_fingerprint="fp-test",
        ml_config_fingerprint_payload={"mode": "test"},
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["method_basis"]["models"][config.MODEL_IFOREST]["role"] == "primary_runtime_anomaly_score"
    assert payload["capture_semantics"]["pcapdroid_version"] == "1.2.3"
    assert payload["windowing"]["window_size_s"] == 10.0
    assert read_ml_config_fingerprint(out_dir) == "fp-test"


def test_write_cohort_status_validates_reason_codes(tmp_path: Path) -> None:
    run_inputs = _run_inputs(tmp_path)

    write_cohort_status(
        run_inputs,
        status="EXCLUDED",
        reason_code="ML_SKIPPED_BAD_IDENTITY_HASH",
        details={"reason": "unit"},
    )

    status_path = run_inputs.run_dir / "analysis" / "ml" / config.ML_SCHEMA_LABEL / "cohort_status.json"
    payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert payload["reason_code"] == "ML_SKIPPED_BAD_IDENTITY_HASH"
    assert payload["identity"]["base_apk_sha256"] == "a" * 64
