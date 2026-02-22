from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.DynamicAnalysis.tools.evidence.freeze_manifest import (
    build_dataset_freeze_manifest,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _mk_run(
    evidence_root: Path,
    run_id: str,
    *,
    run_profile: str,
    valid_dataset_run: bool = True,
    window_count: int = 25,
) -> None:
    run_dir = evidence_root / run_id
    run_idx = int(run_id[-1]) if run_id[-1].isdigit() else 0
    version_code = f"1{run_id[-1]}"
    base_sha = ("a" * 63) + run_id[-1]
    artifact_set_hash = ("b" * 63) + run_id[-1]
    signer_set_hash = ("c" * 63) + run_id[-1]
    static_handoff_hash = ("d" * 63) + run_id[-1]

    operator = {"run_profile": run_profile, "capture_policy_version": 1}
    if run_profile.startswith("interaction_scripted"):
        operator.update(
            {
                "script_hash": ("e" * 63) + run_id[-1],
                "script_exit_code": 0,
                "script_end_marker": True,
                "step_count_planned": 3,
                "step_count_completed": 3,
                "script_timing_within_tolerance": True,
            }
        )

    pcap_rel = "artifacts/pcap/capture.pcap"
    (run_dir / pcap_rel).parent.mkdir(parents=True, exist_ok=True)
    (run_dir / pcap_rel).write_bytes(b"\x00\x01")
    _write_json(
        run_dir / "run_manifest.json",
        {
            "started_at": f"2026-02-22T08:0{run_id[-1]}:00Z",
            "operator": operator,
            "dataset": {
                "valid_dataset_run": valid_dataset_run,
                "window_count": window_count,
                "pcap_size_bytes": 60000 + run_idx,
                "sampling_duration_seconds": 180,
            },
            "artifacts": [{"type": "pcapdroid_capture", "relative_path": pcap_rel}],
            "target": {
                "package_name": "com.example.app",
                "version_code": version_code,
                "base_apk_sha256": base_sha,
                "artifact_set_hash": artifact_set_hash,
                "signer_set_hash": signer_set_hash,
                "static_handoff_hash": static_handoff_hash,
                "run_identity": {
                    "version_code": version_code,
                    "base_apk_sha256": base_sha,
                    "artifact_set_hash": artifact_set_hash,
                    "signer_set_hash": signer_set_hash,
                },
            },
        },
    )
    _write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "plan_schema_version": "v1",
            "paper_contract_version": 1,
            "package_name": "com.example.app",
            "version_code": f"1{run_id[-1]}",
            "run_identity": {
                "package_name_lc": "com.example.app",
                "version_code": version_code,
                "base_apk_sha256": base_sha,
                "artifact_set_hash": artifact_set_hash,
                "signer_set_hash": signer_set_hash,
                "static_handoff_hash": static_handoff_hash,
            },
        },
    )
    _write_json(run_dir / "analysis" / "summary.json", {})
    _write_json(run_dir / "analysis" / "pcap_report.json", {"pcap_size_bytes": 2})
    _write_json(run_dir / "analysis" / "pcap_features.json", {})


def _mk_dataset_plan(path: Path) -> None:
    _write_json(
        path,
        {
            "apps": {
                "com.example.app": {
                    "runs": [
                        {
                            "run_id": "r1",
                            "run_profile": "baseline_idle",
                            "valid_dataset_run": True,
                            "counts_toward_quota": True,
                        },
                        {
                            "run_id": "r2",
                            "run_profile": "interaction_scripted",
                            "valid_dataset_run": True,
                            "counts_toward_quota": True,
                        },
                        {
                            "run_id": "r3",
                            "run_profile": "interaction_scripted",
                            "valid_dataset_run": True,
                            "counts_toward_quota": True,
                        },
                    ]
                }
            }
        },
    )


def test_dataset_freeze_fails_if_included_run_not_dataset_valid(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    dataset_plan_path = tmp_path / "dataset_plan.json"
    _mk_dataset_plan(dataset_plan_path)
    _mk_run(evidence_root, "r1", run_profile="baseline_idle")
    _mk_run(evidence_root, "r2", run_profile="interaction_scripted", valid_dataset_run=False)
    _mk_run(evidence_root, "r3", run_profile="interaction_scripted")

    with pytest.raises(RuntimeError, match=r"FREEZE_INSUFFICIENT_ELIGIBLE_RUNS:com\.example\.app:baseline=1/1:interactive=1/2"):
        build_dataset_freeze_manifest(dataset_plan_path=dataset_plan_path, evidence_root=evidence_root)


def test_dataset_freeze_fails_if_included_run_window_count_too_low(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    dataset_plan_path = tmp_path / "dataset_plan.json"
    _mk_dataset_plan(dataset_plan_path)
    _mk_run(evidence_root, "r1", run_profile="baseline_idle")
    _mk_run(evidence_root, "r2", run_profile="interaction_scripted", window_count=10)
    _mk_run(evidence_root, "r3", run_profile="interaction_scripted")

    with pytest.raises(RuntimeError, match=r"FREEZE_INSUFFICIENT_ELIGIBLE_RUNS:com\.example\.app:baseline=1/1:interactive=1/2"):
        build_dataset_freeze_manifest(dataset_plan_path=dataset_plan_path, evidence_root=evidence_root)


def test_dataset_freeze_selects_deterministic_best_runs_and_reports_extras(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    dataset_plan_path = tmp_path / "dataset_plan.json"
    _mk_dataset_plan(dataset_plan_path)
    # baseline
    _mk_run(evidence_root, "r1", run_profile="baseline_idle", window_count=30)
    # interactive candidates
    _mk_run(evidence_root, "r2", run_profile="interaction_scripted", window_count=20)
    _mk_run(evidence_root, "r3", run_profile="interaction_scripted", window_count=35)
    _mk_run(evidence_root, "r4", run_profile="interaction_scripted", window_count=50)

    payload = build_dataset_freeze_manifest(dataset_plan_path=dataset_plan_path, evidence_root=evidence_root)
    app = payload["apps"]["com.example.app"]
    assert app["baseline_run_ids"] == ["r1"]
    # Top-2 by quality should be r4 then r3.
    assert app["interactive_run_ids"] == ["r4", "r3"]
    assert payload["legacy_runs_present"] is False
    reasons = payload.get("excluded_reason_counts_by_app", {}).get("com.example.app", {})
    assert int(reasons.get("EXCLUDED_NOT_SELECTED_BY_DETERMINISTIC_RANK", 0)) == 1


def test_dataset_freeze_fails_closed_when_evidence_root_missing(tmp_path: Path) -> None:
    dataset_plan_path = tmp_path / "dataset_plan.json"
    _mk_dataset_plan(dataset_plan_path)
    missing_root = tmp_path / "missing-evidence"
    with pytest.raises(RuntimeError, match=r"FREEZE_BLOCKED_NO_EVIDENCE_ROOT:"):
        build_dataset_freeze_manifest(dataset_plan_path=dataset_plan_path, evidence_root=missing_root)
