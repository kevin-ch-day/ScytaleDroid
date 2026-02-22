from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.DynamicAnalysis.ml.snapshot_freeze import build_snapshot_freeze_manifest


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _mk_run(root: Path, run_id: str, *, plan_schema_version: str) -> Path:
    run_dir = root / run_id
    pcap_rel = "artifacts/pcap/capture.pcap"
    (run_dir / pcap_rel).parent.mkdir(parents=True, exist_ok=True)
    (run_dir / pcap_rel).write_bytes(b"\x00\x01")
    _write_json(
        run_dir / "run_manifest.json",
        {
            "artifacts": [{"type": "pcapdroid_capture", "relative_path": pcap_rel}],
            "target": {"package_name": "com.example.app"},
        },
    )
    _write_json(
        run_dir / "inputs" / "static_dynamic_plan.json",
        {
            "plan_schema_version": plan_schema_version,
            "paper_contract_version": 1,
            "package_name": "com.example.app",
            "version_code": f"123-{run_id}",
            "run_identity": {
                "package_name_lc": "com.example.app",
                "version_code": f"123-{run_id}",
                "base_apk_sha256": ("a" * 63) + run_id[-1],
                "artifact_set_hash": ("b" * 63) + run_id[-1],
                "signer_set_hash": ("c" * 63) + run_id[-1],
            },
        },
    )
    _write_json(run_dir / "analysis" / "summary.json", {})
    _write_json(run_dir / "analysis" / "pcap_report.json", {"pcap_size_bytes": 2})
    _write_json(run_dir / "analysis" / "pcap_features.json", {})
    return run_dir


def test_snapshot_freeze_rejects_mixed_plan_schema_versions(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    run1 = _mk_run(evidence_root, "r1", plan_schema_version="v1")
    run2 = _mk_run(evidence_root, "r2", plan_schema_version="v2")
    selection_manifest_path = tmp_path / "selection_manifest.json"
    _write_json(
        selection_manifest_path,
        {
            "selector_type": "freeze",
            "selection_manifest_sha256": "x",
            "inclusion": {
                "included_run_ids": ["r1", "r2"],
                "runs": {
                    "r1": {
                        "evidence_pack_path": str(run1),
                        "package_name": "com.example.app",
                        "run_profile": "baseline_idle",
                    },
                    "r2": {
                        "evidence_pack_path": str(run2),
                        "package_name": "com.example.app",
                        "run_profile": "interactive_use",
                    },
                },
            },
        },
    )
    with pytest.raises(RuntimeError, match="FREEZE_MIXED_SCHEMA_VERSION"):
        build_snapshot_freeze_manifest(selection_manifest_path=selection_manifest_path, evidence_root=evidence_root)
