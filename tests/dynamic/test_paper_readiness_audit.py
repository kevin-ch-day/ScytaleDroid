from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.tools.evidence.paper_readiness_audit import (
    run_paper_readiness_audit,
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

    summary = run_paper_readiness_audit(evidence_root=evidence_root, out_dir=out_dir)
    assert summary.total_runs == 2
    assert summary.valid_runs == 2
    assert summary.missing_capture_policy_version == 1
    assert summary.capture_policy_version_mismatch == 0
    assert summary.missing_signer_set_hash == 1
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
    summary = run_paper_readiness_audit(out_dir=out_dir)
    assert summary.total_runs == 1
    assert summary.evidence_root.endswith("output/evidence/dynamic")


def test_paper_readiness_audit_no_runs_is_no_go_with_reasons(tmp_path: Path) -> None:
    evidence_root = tmp_path / "empty-evidence"
    out_dir = tmp_path / "audit"

    summary = run_paper_readiness_audit(evidence_root=evidence_root, out_dir=out_dir)
    assert summary.total_runs == 0
    assert summary.valid_runs == 0
    assert summary.result == "NO_GO"
    assert "NO_EVIDENCE_PACKS_FOUND" in summary.reasons
    assert "NO_VALID_RUNS" in summary.reasons
    assert Path(summary.report_path).exists()


def test_paper_readiness_audit_surfaces_static_runs_hint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "audit"
    static_root = tmp_path / "evidence" / "static_runs" / "1"
    _write_json(static_root / "run_manifest.json", {"static_run_id": 1})

    summary = run_paper_readiness_audit(out_dir=out_dir)
    assert summary.total_runs == 0
    assert summary.static_runs_hint == 1
    assert summary.result == "NO_GO"
