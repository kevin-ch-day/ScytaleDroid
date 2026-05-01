from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_orchestrator import run_ml_on_evidence_packs
from scytaledroid.DynamicAnalysis.ml.io.ml_output_paths import MLOutputPaths
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as config


def _write_minimal_v1_outputs(run_dir: Path) -> None:
    paths = MLOutputPaths(run_dir=run_dir, schema_label=config.ML_SCHEMA_LABEL)
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    # Minimal placeholder files for "complete v1 outputs".
    paths.model_manifest_path.write_text("{}", encoding="utf-8")
    paths.summary_path.write_text("{}", encoding="utf-8")
    paths.iforest_scores_path.write_text("window_start_s,window_end_s,score,threshold,is_anomalous\n", encoding="utf-8")
    paths.ocsvm_scores_path.write_text("window_start_s,window_end_s,score,threshold,is_anomalous\n", encoding="utf-8")


def test_reuse_existing_outputs_requires_fingerprint_and_does_not_write(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)

    rid = "run_1"
    run_dir = evidence_root / rid
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_minimal_v1_outputs(run_dir)

    freeze = {
        "included_run_ids": [rid],
        "included_run_checksums": {rid: {"sha256": "x"}},
        "apps": {
            "com.example.app": {
                "baseline_run_ids": [rid],
                "interactive_run_ids": [rid, rid],
            }
        },
    }
    freeze_path = tmp_path / "dataset_freeze.json"
    freeze_path.write_text(json.dumps(freeze), encoding="utf-8")

    before = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())

    with pytest.raises(RuntimeError, match="ml_config_fingerprint missing"):
        run_ml_on_evidence_packs(
            output_root=evidence_root,
            freeze_manifest_path=freeze_path,
            reuse_existing_outputs=True,
        )

    after = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert after == before, "expected fail-closed reuse to perform zero filesystem writes"

