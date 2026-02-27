from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def test_profile_v3_manifest_build_smoke(tmp_path: Path) -> None:
    base = tmp_path / "base_freeze.json"
    _write_json(
        base,
        {
            "included_run_ids": ["a", "b", "b"],
            "freeze_dataset_hash": "deadbeef",
            "apps": {
                "com.example.app": {
                    "baseline_run_ids": ["a"],
                    "interactive_run_ids": ["b"],
                    "included_run_ids": ["a", "b"],
                }
            },
        },
    )
    evidence = tmp_path / "evidence"
    _write_json(
        evidence / "a" / "run_manifest.json",
        {"target": {"package_name": "com.example.app"}, "operator": {"run_profile": "baseline_idle"}},
    )
    _write_json(
        evidence / "b" / "run_manifest.json",
        {"target": {"package_name": "com.example.app"}, "operator": {"run_profile": "interaction_scripted"}},
    )
    _write_json(
        evidence / "c" / "run_manifest.json",
        {"target": {"package_name": "com.example.app"}, "operator": {"run_profile": "interaction_scripted"}},
    )
    out = tmp_path / "profile_v3_manifest.json"
    script = Path(__file__).resolve().parents[2] / "scripts" / "profile_tools" / "profile_v3_manifest_build.py"
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--base-freeze",
            str(base),
            "--import-from-base",
            "--add-run-id",
            "c",
            "--evidence-root",
            str(evidence),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["profile_id"] == "profile_v3_structural"
    assert payload["included_run_ids"] == ["a", "b", "c"]


def test_profile_v3_catalog_validate_missing_package(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    run_dir = evidence / "r1"
    _write_json(run_dir / "run_manifest.json", {"target": {"package_name": "com.missing.pkg"}, "operator": {"run_profile": "baseline_idle"}})

    manifest = tmp_path / "profile_v3_manifest.json"
    _write_json(manifest, {"profile_id": "profile_v3_structural", "included_run_ids": ["r1"]})

    catalog = tmp_path / "catalog.json"
    _write_json(catalog, {"com.other.pkg": {"app": "Other", "app_category": "social_messaging"}})

    script = Path(__file__).resolve().parents[2] / "scripts" / "profile_tools" / "profile_v3_catalog_validate.py"
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--manifest",
            str(manifest),
            "--catalog",
            str(catalog),
            "--evidence-root",
            str(evidence),
            "--emit-json-snippet",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "com.missing.pkg" in proc.stdout
