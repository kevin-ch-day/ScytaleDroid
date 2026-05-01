"""Harvest filesystem verification (manifests / receipts)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.Config import app_config


@pytest.fixture(autouse=True)
def _isolate_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))


def test_verify_passes_when_manifest_matches_artifact() -> None:
    from scytaledroid.DeviceAnalysis.evidence_verify.filesystem import verify_harvest_filesystem
    from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes

    data = Path.cwd() / "data"
    harvest_base = data / "device_apks"
    pkg_dir = harvest_base / "SER" / "runs" / "run1" / "com.example.a" / "App_v1_1.0"
    pkg_dir.mkdir(parents=True)

    apk = pkg_dir / "base.apk"
    apk.write_bytes(b"fake-apk-body")
    hashes = compute_hashes(apk)

    session = "run1"
    rel_manifest = "SER/runs/run1/com.example.a/App_v1_1.0/harvest_package_manifest.json"
    rel_art = "SER/runs/run1/com.example.a/App_v1_1.0/base.apk"

    receipts_dir = data / "receipts" / "harvest" / session
    receipts_dir.mkdir(parents=True)

    manifest_path = pkg_dir / "harvest_package_manifest.json"

    doc: dict[str, object] = {
        "schema": "harvest_package_manifest_v1",
        "package": {
            "package_name": "com.example.a",
            "session_label": session,
        },
        "execution": {
            "observed_artifacts": [
                {
                    "file_name": "base.apk",
                    "pull_outcome": "written",
                    "local_artifact_path": rel_art,
                    "sha256": hashes["sha256"],
                },
            ]
        },
        "comparison": {"matches_planned_artifacts": True},
        "paths": {
            "legacy_manifest_path": rel_manifest,
            "receipt_path": "data/receipts/harvest/run1/com.example.a.json",
        },
    }

    receipts_dir.joinpath("com.example.a.json").write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")

    issues, exit_code = verify_harvest_filesystem(harvest_root=harvest_base, data_root=data)
    errs = [i for i in issues if i.severity == "error"]
    assert exit_code == 0, errs
    assert errs == []


def test_verify_fails_on_hash_mismatch() -> None:
    from scytaledroid.DeviceAnalysis.evidence_verify.filesystem import verify_harvest_filesystem

    data = Path.cwd() / "data"
    harvest_base = data / "device_apks"
    pkg_dir = harvest_base / "SER" / "runs" / "run1" / "com.example.b" / "App_v2_2"
    pkg_dir.mkdir(parents=True)
    apk = pkg_dir / "base.apk"
    apk.write_bytes(b"x")

    rel_manifest = "SER/runs/run1/com.example.b/App_v2_2/harvest_package_manifest.json"
    rel_art = "SER/runs/run1/com.example.b/App_v2_2/base.apk"
    session = "run1"
    receipts_dir = data / "receipts" / "harvest" / session
    receipts_dir.mkdir(parents=True)

    doc = {
        "schema": "harvest_package_manifest_v1",
        "package": {"package_name": "com.example.b", "session_label": session},
        "execution": {
            "observed_artifacts": [
                {
                    "file_name": "base.apk",
                    "pull_outcome": "written",
                    "local_artifact_path": rel_art,
                    "sha256": "0" * 64,
                },
            ]
        },
        "comparison": {"matches_planned_artifacts": True},
        "paths": {
            "legacy_manifest_path": rel_manifest,
            "receipt_path": "data/receipts/harvest/run1/com.example.b.json",
        },
    }

    receipts_dir.joinpath("com.example.b.json").write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    pkg_dir.joinpath("harvest_package_manifest.json").write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")

    _issues, exit_code = verify_harvest_filesystem(harvest_root=harvest_base, data_root=data)
    assert exit_code == 1
