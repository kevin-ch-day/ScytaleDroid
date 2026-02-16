from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "publication" / "export_manifest_gate.py"
_FIXTURE_ROOT = _ROOT / "tests" / "fixtures" / "publication"
_MANIFEST = _FIXTURE_ROOT / "paper2_export_manifest.json"
_BUNDLE = _FIXTURE_ROOT / "paper2_bundle"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        cwd=_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )


def test_export_manifest_gate_script_passes(tmp_path: Path):
    output = tmp_path / "diff.json"
    proc = _run("--manifest", str(_MANIFEST), "--artifact-root", str(_BUNDLE), "--output", str(output))
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["result"]["pass"] is True


def test_export_manifest_gate_script_fails_on_drift(tmp_path: Path):
    work_bundle = tmp_path / "bundle"
    shutil.copytree(_BUNDLE, work_bundle)
    (work_bundle / "tables" / "table_7_exposure_deviation_summary.csv").write_text(
        "app,package_name,rdi_if_interactive\nAlpha App,com.example.alpha,9.999\n",
        encoding="utf-8",
    )
    output = tmp_path / "diff.json"
    proc = _run("--manifest", str(_MANIFEST), "--artifact-root", str(work_bundle), "--output", str(output))
    assert proc.returncode == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["result"]["pass"] is False
    assert payload["result"]["diff_counts"]["disallowed"] >= 1

