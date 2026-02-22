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
    pcap_rel = "artifacts/pcap/capture.pcap"
    (run_dir / pcap_rel).parent.mkdir(parents=True, exist_ok=True)
    (run_dir / pcap_rel).write_bytes(b"\x00\x01")
    _write_json(
        run_dir / "run_manifest.json",
        {
            "operator": {"run_profile": run_profile, "capture_policy_version": 1},
            "dataset": {"valid_dataset_run": valid_dataset_run, "window_count": window_count},
            "artifacts": [{"type": "pcapdroid_capture", "relative_path": pcap_rel}],
            "target": {"package_name": "com.example.app"},
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
                "version_code": f"1{run_id[-1]}",
                "base_apk_sha256": ("a" * 63) + run_id[-1],
                "artifact_set_hash": ("b" * 63) + run_id[-1],
                "signer_set_hash": ("c" * 63) + run_id[-1],
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

    with pytest.raises(RuntimeError, match="FREEZE_EVIDENCE_INVALID_DATASET_RUN:r2"):
        build_dataset_freeze_manifest(dataset_plan_path=dataset_plan_path, evidence_root=evidence_root)


def test_dataset_freeze_fails_if_included_run_window_count_too_low(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    dataset_plan_path = tmp_path / "dataset_plan.json"
    _mk_dataset_plan(dataset_plan_path)
    _mk_run(evidence_root, "r1", run_profile="baseline_idle")
    _mk_run(evidence_root, "r2", run_profile="interaction_scripted", window_count=10)
    _mk_run(evidence_root, "r3", run_profile="interaction_scripted")

    with pytest.raises(RuntimeError, match=r"FREEZE_EVIDENCE_WINDOW_COUNT_INVALID:r2:10"):
        build_dataset_freeze_manifest(dataset_plan_path=dataset_plan_path, evidence_root=evidence_root)

