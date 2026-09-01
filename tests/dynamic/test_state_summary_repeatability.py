from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.tools.evidence import state_summary


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _mk_run(
    root: Path,
    run_id: str,
    *,
    complete: bool,
) -> None:
    run_dir = root / run_id
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "ml" / "v1").mkdir(parents=True, exist_ok=True)
    (run_dir / "captures").mkdir(parents=True, exist_ok=True)

    if complete:
        (run_dir / "captures" / "app.pcapng").write_bytes(b"pcap")

    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": run_id,
            "status": "success",
            "target": {"package_name": f"com.example.{run_id}"},
            "dataset": {
                "tier": "dataset",
                "window_count": 24 if complete else None,
                "sampling_duration_seconds": 120 if complete else None,
            },
            "artifacts": [
                {"type": "pcapdroid_capture", "relative_path": "captures/app.pcapng"},
            ],
        },
    )
    _write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "package_name": f"com.example.{run_id}",
            "static_run_id": 123 if complete else None,
            "run_identity": {
                "static_run_id": 123 if complete else None,
                "run_signature": "r" * 64 if complete else None,
                "run_signature_version": "v1" if complete else None,
                "artifact_set_hash": "a" * 64 if complete else None,
                "base_apk_sha256": "b" * 64 if complete else None,
                "static_handoff_hash": "c" * 64 if complete else None,
                "identity_valid": True if complete else False,
            },
        },
    )
    _write_json(run_dir / "analysis" / "summary.json", {"telemetry": {}})
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {"pcap_size_bytes": 2048 if complete else 0},
    )
    _write_json(run_dir / "analysis" / "pcap_features.json", {"proxies": {"tls_ratio": 0.4}})
    if complete:
        _write_json(
            run_dir / "analysis" / "ml" / "v1" / "baseline_threshold.json",
            {"models": {"iforest": {"threshold_value": 0.7}}},
        )
        _write_json(
            run_dir / "analysis" / "ml" / "v1" / "dars_v1.json",
            {"scores": {"iforest": {"dars_v1": 0.1}}},
        )
        _write_json(
            run_dir / "analysis" / "ml" / "v1" / "ml_summary.json",
            {
                "windowing": {"window_size_s": 10, "stride_s": 5},
                "models": {"iforest": {"threshold_value": 0.7, "dars_v1": {"dars_v1": 0.1}}},
                "freeze_manifest_sha256": "f" * 64,
                "freeze_dataset_hash": "d" * 64,
            },
        )
        _write_json(
            run_dir / "analysis" / "ml" / "v1" / "model_manifest.json",
            {
                "freeze_manifest_sha256": "f" * 64,
                "freeze_dataset_hash": "d" * 64,
            },
        )
    else:
        _write_json(
            run_dir / "analysis" / "ml" / "v1" / "ml_summary.json",
            {"windowing": {"window_size_s": 10, "stride_s": 5}, "models": {}},
        )


def test_build_repeatability_summary_counts_ready_and_blocked_runs(monkeypatch, tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    data_root = tmp_path / "data"
    evidence_root = output_root / "evidence" / "dynamic"
    _mk_run(evidence_root, "run-good", complete=True)
    _mk_run(evidence_root, "run-bad", complete=False)

    _write_json(
        data_root / "archive" / "dataset_freeze.json",
        {
            "freeze_role": "canonical",
            "paper_contract_hash": "z" * 64,
            "included_run_ids": ["run-good"],
        },
    )
    _write_json(output_root / "publication" / "manifests" / "bundle.json", {"ok": True})

    monkeypatch.setattr(state_summary.app_config, "OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(state_summary.app_config, "DATA_DIR", str(data_root))
    monkeypatch.setattr(
        state_summary,
        "resolve_dataset_freeze_read_path",
        lambda: data_root / "archive" / "dataset_freeze.json",
    )

    out = state_summary.build_repeatability_summary()

    assert out["runs_total"] == 2
    assert out["runs_with_manifest"] == 2
    assert out["runs_identity_complete"] == 1
    assert out["runs_static_link_ready"] == 1
    assert out["runs_pcap_present"] == 1
    assert out["runs_features_present"] == 2
    assert out["runs_windowing_recorded"] == 1
    assert out["runs_threshold_present"] == 1
    assert out["runs_rdi_ready"] == 1
    assert out["runs_freeze_stamped"] == 1
    assert out["runs_repeatability_ready"] == 1
    assert out["publication_manifests_present"] is True
    assert out["publication_manifest_files"] == 1
    assert out["freeze_role"] == "canonical"
    assert out["issue_counts"]["identity_incomplete"] == 1
    assert out["issue_counts"]["pcap_missing"] == 1
    assert out["issue_counts"]["baseline_threshold_missing"] == 1
    assert out["issue_counts"]["rdi_missing"] == 1


def test_build_repeatability_summary_handles_missing_evidence_root(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(state_summary.app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(state_summary.app_config, "DATA_DIR", str(tmp_path / "data"))

    out = state_summary.build_repeatability_summary()

    assert out["evidence_root_exists"] is False
    assert out["runs_total"] == 0
    assert out["runs_repeatability_ready"] == 0
    assert out["issue_counts"] == {}
