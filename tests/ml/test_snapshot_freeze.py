from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.snapshot_freeze import build_snapshot_freeze_manifest

HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_run(evidence_root: Path, run_id: str) -> Path:
    run_dir = evidence_root / run_id
    _write_json(
        run_dir / "run_manifest.json",
        {
            "artifacts": [],
            "target": {
                "package_name": "com.example.app",
            },
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
                "base_apk_sha256": HEX_A,
                "artifact_set_hash": HEX_B,
                "signer_set_hash": HEX_C,
            },
        },
    )
    _write_json(run_dir / "analysis" / "summary.json", {"ok": True})
    _write_json(run_dir / "analysis" / "pcap_report.json", {"pcap_size_bytes": 1234})
    _write_json(run_dir / "analysis" / "pcap_features.json", {"windows": []})
    return run_dir


def test_snapshot_freeze_records_repeated_build_identity_as_observations(tmp_path: Path) -> None:
    evidence_root = tmp_path / "data" / "evidence" / "dynamic"
    run_a = _write_run(evidence_root, "run-a")
    run_b = _write_run(evidence_root, "run-b")
    selection_manifest = tmp_path / "selection_manifest.json"
    _write_json(
        selection_manifest,
        {
            "selector_type": "query",
            "selection_manifest_sha256": "f" * 64,
            "inclusion": {
                "included_run_ids": ["run-a", "run-b"],
                "runs": {
                    "run-a": {
                        "evidence_pack_path": str(run_a),
                        "package_name": "com.example.app",
                        "mode": "baseline",
                    },
                    "run-b": {
                        "evidence_pack_path": str(run_b),
                        "package_name": "com.example.app",
                        "mode": "interactive",
                    },
                },
            },
        },
    )

    payload = build_snapshot_freeze_manifest(
        selection_manifest_path=selection_manifest,
        evidence_root=evidence_root,
    )

    assert payload["included_run_ids"] == ["run-a", "run-b"]
    assert payload["duplicate_identity_groups"] == [
        {
            "identity": {
                "package_name_lc": "com.example.app",
                "version_code": "123",
                "base_apk_sha256": HEX_A,
                "artifact_set_hash": HEX_B,
                "signer_set_hash": HEX_C,
            },
            "run_ids": ["run-a", "run-b"],
        }
    ]

