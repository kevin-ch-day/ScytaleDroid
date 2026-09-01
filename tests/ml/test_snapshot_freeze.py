from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
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


def _write_selection(path: Path, run_id: str, run_dir: Path | None = None) -> None:
    run_metadata = {"package_name": "com.example.app"}
    if run_dir is not None:
        run_metadata["evidence_pack_path"] = str(run_dir)
    _write_json(
        path,
        {
            "selector_type": "query",
            "inclusion": {
                "included_run_ids": [run_id],
                "runs": {run_id: run_metadata},
            },
        },
    )


def test_snapshot_freeze_rejects_pcap_path_outside_run(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    run_dir = _write_run(evidence_root, "run-a")
    manifest_path = run_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"] = [
        {"type": "pcapdroid_capture", "relative_path": "../../outside.pcap"}
    ]
    _write_json(manifest_path, manifest)
    (tmp_path / "outside.pcap").write_bytes(b"outside")
    selection = tmp_path / "selection.json"
    _write_selection(selection, "run-a", run_dir)

    with pytest.raises(RuntimeError, match="SNAPSHOT_FREEZE_UNSAFE_ARTIFACT_PATH:run-a"):
        build_snapshot_freeze_manifest(
            selection_manifest_path=selection,
            evidence_root=evidence_root,
        )


def test_snapshot_freeze_rejects_stale_reported_pcap_hash(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    run_dir = _write_run(evidence_root, "run-a")
    pcap = run_dir / "capture.pcap"
    pcap.write_bytes(b"captured-packets")
    manifest_path = run_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"] = [
        {"type": "pcapdroid_capture", "relative_path": "capture.pcap"}
    ]
    _write_json(manifest_path, manifest)
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {
            "pcap_size_bytes": pcap.stat().st_size,
            "pcap_sha256": "0" * 64,
        },
    )
    selection = tmp_path / "selection.json"
    _write_selection(selection, "run-a", run_dir)

    with pytest.raises(RuntimeError, match="SNAPSHOT_FREEZE_PCAP_REPORT_HASH_MISMATCH:run-a"):
        build_snapshot_freeze_manifest(
            selection_manifest_path=selection,
            evidence_root=evidence_root,
        )

    assert hashlib.sha256(pcap.read_bytes()).hexdigest() != "0" * 64


def test_snapshot_freeze_rejects_run_id_escape_when_no_explicit_pack_path(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    selection = tmp_path / "selection.json"
    _write_selection(selection, "../outside")

    with pytest.raises(RuntimeError, match="SNAPSHOT_FREEZE_UNSAFE_RUN_ID"):
        build_snapshot_freeze_manifest(
            selection_manifest_path=selection,
            evidence_root=evidence_root,
        )


def test_snapshot_freeze_rejects_explicit_pack_path_outside_evidence_root(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    outside_run = _write_run(tmp_path / "outside", "run-a")
    selection = tmp_path / "selection.json"
    _write_selection(selection, "run-a", outside_run)

    with pytest.raises(RuntimeError, match="SNAPSHOT_FREEZE_UNSAFE_EVIDENCE_PATH:run-a"):
        build_snapshot_freeze_manifest(
            selection_manifest_path=selection,
            evidence_root=evidence_root,
        )


def test_snapshot_freeze_rejects_explicit_pack_path_for_different_run(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    other_run = _write_run(evidence_root, "run-b")
    selection = tmp_path / "selection.json"
    _write_selection(selection, "run-a", other_run)

    with pytest.raises(RuntimeError, match="SNAPSHOT_FREEZE_EVIDENCE_PATH_ID_MISMATCH:run-a"):
        build_snapshot_freeze_manifest(
            selection_manifest_path=selection,
            evidence_root=evidence_root,
        )


def test_snapshot_freeze_rejects_manifest_run_id_mismatch(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    run_dir = _write_run(evidence_root, "run-a")
    manifest_path = run_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["dynamic_run_id"] = "run-b"
    _write_json(manifest_path, manifest)
    selection = tmp_path / "selection.json"
    _write_selection(selection, "run-a", run_dir)

    with pytest.raises(RuntimeError, match="SNAPSHOT_FREEZE_MANIFEST_RUN_ID_MISMATCH:run-a"):
        build_snapshot_freeze_manifest(
            selection_manifest_path=selection,
            evidence_root=evidence_root,
        )
