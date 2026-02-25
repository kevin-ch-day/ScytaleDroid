from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
    run_freeze_readiness_audit,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def test_paper_readiness_audit_detects_policy_signer_and_window_issues(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    out_dir = tmp_path / "audit"

    # Good run
    _write_json(
        evidence_root / "r-good" / "run_manifest.json",
        {
            "dynamic_run_id": "r-good",
            "operator": {"capture_policy_version": 1},
            "target": {"package_name": "com.example.app", "signer_set_hash": "a" * 64},
            "dataset": {"valid_dataset_run": True, "window_count": 25},
        },
    )

    # Bad run: missing policy/signer and weak windows
    _write_json(
        evidence_root / "r-bad" / "run_manifest.json",
        {
            "dynamic_run_id": "r-bad",
            "operator": {},
            "target": {"package_name": "com.example.app"},
            "dataset": {"valid_dataset_run": True, "window_count": 10},
        },
    )

    summary = run_freeze_readiness_audit(evidence_root=evidence_root, out_dir=out_dir)
    assert summary.total_runs == 2
    assert summary.valid_runs == 2
    assert summary.paper_eligible_runs == 0
    assert summary.missing_run_manifest_dirs == 0
    assert summary.missing_capture_policy_version == 1
    assert summary.capture_policy_version_mismatch == 0
    assert summary.missing_signer_set_hash == 1
    assert summary.identity_mismatch == 0
    assert summary.missing_window_count == 0
    assert summary.window_count_below_min == 1
    assert summary.evidence_root == str(evidence_root)
    assert summary.runs_discovered_from == "filesystem"
    assert summary.result == "NO_GO"
    assert "QUOTA_NOT_SATISFIED" in summary.reasons
    assert Path(summary.report_path).exists()


def test_paper_readiness_audit_uses_default_output_root_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "output" / "audit" / "dynamic"
    _write_json(
        tmp_path / "output" / "evidence" / "dynamic" / "r1" / "run_manifest.json",
        {
            "dynamic_run_id": "r1",
            "operator": {"capture_policy_version": 1},
            "target": {"package_name": "com.example.app", "signer_set_hash": "a" * 64},
            "dataset": {"valid_dataset_run": True, "window_count": 25},
        },
    )
    summary = run_freeze_readiness_audit(out_dir=out_dir)
    assert summary.total_runs == 1
    assert summary.missing_run_manifest_dirs == 0
    assert summary.evidence_root.endswith("output/evidence/dynamic")


def test_paper_readiness_audit_no_runs_is_no_go_with_reasons(tmp_path: Path) -> None:
    evidence_root = tmp_path / "empty-evidence"
    out_dir = tmp_path / "audit"

    summary = run_freeze_readiness_audit(evidence_root=evidence_root, out_dir=out_dir)
    assert summary.total_runs == 0
    assert summary.valid_runs == 0
    assert summary.paper_eligible_runs == 0
    assert summary.missing_run_manifest_dirs == 0
    assert summary.result == "NO_GO"
    assert "NO_EVIDENCE_PACKS_FOUND" in summary.reasons
    assert "NO_VALID_RUNS" in summary.reasons
    assert "NO_PAPER_ELIGIBLE_RUNS" in summary.reasons
    assert Path(summary.report_path).exists()


def test_paper_readiness_audit_surfaces_static_runs_hint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "audit"
    static_root = tmp_path / "evidence" / "static_runs" / "1"
    _write_json(static_root / "run_manifest.json", {"static_run_id": 1})

    summary = run_freeze_readiness_audit(out_dir=out_dir)
    assert summary.total_runs == 0
    assert summary.paper_eligible_runs == 0
    assert summary.missing_run_manifest_dirs == 0
    assert summary.static_runs_hint == 1
    assert summary.result == "NO_GO"


def test_paper_readiness_audit_detects_identity_mismatch(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    out_dir = tmp_path / "audit"
    run_dir = evidence_root / "r-mismatch"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "r-mismatch",
            "operator": {"capture_policy_version": 1, "run_profile": "baseline_idle"},
            "target": {
                "package_name": "com.example.app",
                "version_code": "999",
                "run_identity": {
                    "version_code": "999",
                    "base_apk_sha256": "a" * 64,
                    "artifact_set_hash": "b" * 64,
                    "signer_set_hash": "c" * 64,
                },
                "signer_set_hash": "c" * 64,
            },
            "dataset": {"valid_dataset_run": True, "window_count": 25},
        },
    )
    _write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "package_name": "com.example.app",
            "version_code": "123",
            "run_identity": {
                "package_name_lc": "com.example.app",
                "version_code": "123",
                "base_apk_sha256": "a" * 64,
                "artifact_set_hash": "b" * 64,
                "signer_set_hash": "c" * 64,
                "static_handoff_hash": "d" * 64,
            },
        },
    )
    summary = run_freeze_readiness_audit(evidence_root=evidence_root, out_dir=out_dir)
    assert summary.total_runs == 1
    assert summary.paper_eligible_runs == 0
    assert summary.missing_run_manifest_dirs == 0
    assert summary.identity_mismatch == 1
    assert "IDENTITY_MISMATCH" in summary.reasons


def test_paper_readiness_audit_flags_orphan_evidence_dirs(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    out_dir = tmp_path / "audit"
    (evidence_root / "orphan-run").mkdir(parents=True, exist_ok=True)
    _write_json(
        evidence_root / "r-good" / "run_manifest.json",
        {
            "dynamic_run_id": "r-good",
            "operator": {"capture_policy_version": 1},
            "target": {"package_name": "com.example.app", "signer_set_hash": "a" * 64},
            "dataset": {"valid_dataset_run": True, "window_count": 25},
        },
    )
    summary = run_freeze_readiness_audit(evidence_root=evidence_root, out_dir=out_dir)
    assert summary.total_runs == 1
    assert summary.missing_run_manifest_dirs == 1
    assert "INCOMPLETE_EVIDENCE_DIRS_PRESENT" in summary.reasons


def test_paper_readiness_audit_demotes_noncanonical_freeze(tmp_path: Path, monkeypatch) -> None:
    out_dir = tmp_path / "output" / "audit" / "dynamic"
    output_dir = tmp_path / "output"
    data_dir = tmp_path / "data"
    monkeypatch.setattr("scytaledroid.Config.app_config.DATA_DIR", str(data_dir))
    monkeypatch.setattr("scytaledroid.Config.app_config.OUTPUT_DIR", str(output_dir))
    _write_json(
        data_dir / "archive" / "dataset_freeze.json",
        {
            "included_run_ids": ["missing-run"],
            "paper_contract_hash": "a" * 64,
            "freeze_role": "canonical",
        },
    )
    summary = run_freeze_readiness_audit(out_dir=out_dir)
    assert summary.canonical_freeze_demoted_to_legacy is not None
    assert summary.canonical_freeze_role == "none"
    assert summary.freeze_run_ids_total == 0
    assert (data_dir / "archive" / "dataset_freeze.json").exists() is False
    assert list((data_dir / "archive").glob("legacy_freeze_*.json"))
