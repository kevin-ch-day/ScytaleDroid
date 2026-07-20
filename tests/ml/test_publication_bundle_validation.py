from __future__ import annotations

import json
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as config
from scytaledroid.DynamicAnalysis.ml.publication_bundle import validation
from scytaledroid.DynamicAnalysis.ml.publication_bundle.manifest_utils import (
    copy_required,
    sha256_stream,
)


def test_sha256_stream_and_copy_required(tmp_path: Path) -> None:
    src = tmp_path / "source.txt"
    dest = tmp_path / "nested" / "dest.txt"
    src.write_text("hello\n", encoding="utf-8")

    copy_required(src, dest, overwrite=True)

    assert dest.read_text(encoding="utf-8") == "hello\n"
    assert sha256_stream(src) == sha256_stream(dest)
    with pytest.raises(RuntimeError, match="Missing required input"):
        copy_required(tmp_path / "missing.txt", tmp_path / "out.txt", overwrite=True)


def test_phrase_lint_report_flags_prohibited_phrase(tmp_path: Path) -> None:
    target = tmp_path / "report.md"
    target.write_text("This sentence says payload bytes.", encoding="utf-8")

    out = validation.write_phrase_lint_report(target_paths=(target,), out_path=tmp_path / "lint.json")
    payload = json.loads(out.read_text(encoding="utf-8"))

    assert payload["ok"] is False
    assert payload["violations"] == [{"path": str(target), "phrase": "payload bytes"}]


def test_required_fields_validation_report_passes_complete_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    freeze = tmp_path / "dataset_freeze.json"
    freeze.write_text(json.dumps({"included_run_ids": ["run-1"]}), encoding="utf-8")
    monkeypatch.setattr(validation, "freeze_anchor_path", lambda: freeze)
    evidence_root = tmp_path / "data" / "evidence" / "dynamic"
    monkeypatch.setattr(validation, "dynamic_evidence_root", lambda: evidence_root)
    monkeypatch.setattr(validation, "resolve_dynamic_run_dir", lambda rid: evidence_root / str(rid))

    manifest = (
        evidence_root
        / "run-1"
        / "analysis"
        / "ml"
        / config.ML_SCHEMA_LABEL
        / "model_manifest.json"
    )
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "seed": 123,
                "windowing": {"window_size_s": 10, "stride_s": 5},
                "models": {
                    config.MODEL_IFOREST: {
                        "threshold_percentile": 95,
                        "np_percentile_method": "linear",
                        "feature_names": ["bytes_per_sec"],
                        "params": {"n_estimators": 100},
                        "training_mode": "baseline_only",
                    }
                },
                "environment": {
                    "deps": {"numpy": "1", "sklearn": "1"},
                    "host_tools": {"tshark": {"version": "4"}},
                },
            }
        ),
        encoding="utf-8",
    )

    out = validation.write_required_fields_validation_report(manifest_dir=tmp_path)
    payload = json.loads(out.read_text(encoding="utf-8"))

    assert payload["paper_grade_ready"] is True
    assert payload["failed_runs"] == 0
    assert payload["missing_by_run"] == {}


def test_determinism_checksums_handles_missing_run_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    freeze = tmp_path / "dataset_freeze.json"
    freeze.write_text(json.dumps({"included_run_ids": ["run-1"]}), encoding="utf-8")
    table_dir = tmp_path / "tables"
    table_dir.mkdir()
    (table_dir / "table_1_rdi_prevalence.csv").write_text("a\n", encoding="utf-8")
    (table_dir / "table_8_model_comparison_metrics.csv").write_text("b\n", encoding="utf-8")

    monkeypatch.setattr(validation, "freeze_anchor_path", lambda: freeze)
    monkeypatch.setattr(validation, "output_locked_runtime_bundle_tables_dir", lambda: table_dir)
    monkeypatch.setattr(validation, "dynamic_evidence_root", lambda: tmp_path / "evidence")
    monkeypatch.setattr(validation, "resolve_dynamic_run_dir", lambda rid: None)

    out = validation.write_determinism_checksums(manifest_dir=tmp_path)
    payload = json.loads(out.read_text(encoding="utf-8"))

    assert payload["freeze_sha256"] == sha256_stream(freeze)
    assert payload["per_run"]["run-1"]["model_manifest_sha256"] is None
    assert payload["table_hashes"]["table_1_rdi_prevalence_csv"] == sha256_stream(
        table_dir / "table_1_rdi_prevalence.csv"
    )
