from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _mk_run(
    *,
    evidence_root: Path,
    run_id: str,
    pkg: str,
    run_profile: str,
    version_code: str = "123",
    pcap_bytes: int = 100_000,
    windows: int = 20,
) -> None:
    """Create a minimal dynamic evidence run that satisfies v3 strict builder checks."""
    run_dir = evidence_root / run_id
    _write_json(
        run_dir / "run_manifest.json",
        {
            "target": {"package_name": pkg, "run_identity": {"version_code": version_code}},
            "operator": {"run_profile": run_profile},
            "artifacts": [{"type": "pcapdroid_capture", "size_bytes": int(pcap_bytes)}],
        },
    )
    # The strict manifest builder currently requires both files for every included run.
    _write_json(run_dir / "analysis" / "ml" / "v1" / "baseline_threshold.json", {"threshold": 0.95})
    # window_scores.csv: DictReader row count is the "windows" proxy.
    rows = ["window_idx,score"]
    for i in range(int(windows)):
        rows.append(f"{i},0.1")
    _write_text(run_dir / "analysis" / "ml" / "v1" / "window_scores.csv", "\n".join(rows) + "\n")


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


def test_profile_v3_manifest_build_strict_blocks_partial_cohort(tmp_path: Path) -> None:
    """Strict mode must fail-closed if the cohort cannot include all 21 apps with idle+scripted coverage."""
    # 21-app catalog.
    pkgs = [f"com.example.app{i:02d}" for i in range(1, 22)]
    catalog = tmp_path / "catalog.json"
    _write_json(catalog, {p: {"app": p, "app_category": "social_messaging"} for p in pkgs})

    evidence = tmp_path / "evidence"

    run_ids: list[str] = []
    # Create complete coverage for 20 apps; leave the last package missing scripted.
    for idx, pkg in enumerate(pkgs, start=1):
        idle_id = f"idle_{idx:02d}"
        run_ids.append(idle_id)
        _mk_run(evidence_root=evidence, run_id=idle_id, pkg=pkg, run_profile="baseline_idle", windows=20)
        if idx < len(pkgs):  # omit scripted run for the last package
            scr_id = f"scr_{idx:02d}"
            run_ids.append(scr_id)
            _mk_run(evidence_root=evidence, run_id=scr_id, pkg=pkg, run_profile="interaction_scripted", windows=20)

    # Base freeze is only used for provenance refs here.
    base = tmp_path / "base_freeze.json"
    _write_json(base, {"freeze_dataset_hash": "deadbeef", "included_run_ids": []})

    out = tmp_path / "profile_v3_manifest.json"
    script = Path(__file__).resolve().parents[2] / "scripts" / "profile_tools" / "profile_v3_manifest_build.py"

    argv: list[str] = [
        sys.executable,
        str(script),
        "--strict",
        "--base-freeze",
        str(base),
        "--catalog",
        str(catalog),
        "--evidence-root",
        str(evidence),
        "--out",
        str(out),
    ]
    for rid in run_ids:
        argv.extend(["--add-run-id", rid])

    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode != 0
    # Fail-closed reason must mention missing required phase coverage for the last package.
    assert "PROFILE_V3_STRICT_NOT_READY" in (proc.stderr + proc.stdout)
    assert f"missing_required_phase\t{pkgs[-1]}\tidle=1\tscripted=0" in (proc.stdout + proc.stderr)
    assert not out.exists()


def test_profile_v3_manifest_build_strict_enforces_min_windows_per_run(tmp_path: Path) -> None:
    """Strict mode must fail if any included run has fewer than MIN_WINDOWS_PER_RUN windows."""
    pkgs = [f"com.example.win{i:02d}" for i in range(1, 22)]
    catalog = tmp_path / "catalog.json"
    _write_json(catalog, {p: {"app": p, "app_category": "social_messaging"} for p in pkgs})
    evidence = tmp_path / "evidence"

    run_ids: list[str] = []
    for idx, pkg in enumerate(pkgs, start=1):
        idle_id = f"idle_{idx:02d}"
        scr_id = f"scr_{idx:02d}"
        run_ids.extend([idle_id, scr_id])
        _mk_run(evidence_root=evidence, run_id=idle_id, pkg=pkg, run_profile="baseline_idle", windows=20)
        # Make exactly one run under-minima.
        windows = 19 if idx == 1 else 20
        _mk_run(evidence_root=evidence, run_id=scr_id, pkg=pkg, run_profile="interaction_scripted", windows=windows)

    base = tmp_path / "base_freeze.json"
    _write_json(base, {"freeze_dataset_hash": "deadbeef", "included_run_ids": []})
    out = tmp_path / "profile_v3_manifest.json"
    script = Path(__file__).resolve().parents[2] / "scripts" / "profile_tools" / "profile_v3_manifest_build.py"

    argv: list[str] = [
        sys.executable,
        str(script),
        "--strict",
        "--base-freeze",
        str(base),
        "--catalog",
        str(catalog),
        "--evidence-root",
        str(evidence),
        "--out",
        str(out),
    ]
    for rid in run_ids:
        argv.extend(["--add-run-id", rid])

    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode != 0
    out_txt = proc.stdout + proc.stderr
    assert "PROFILE_V3_STRICT_NOT_READY" in out_txt
    assert "insufficient_windows\t" in out_txt
    assert not out.exists()


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
