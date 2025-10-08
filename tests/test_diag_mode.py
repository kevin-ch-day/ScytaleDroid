from __future__ import annotations

import json
import subprocess


def _run_diag_json() -> dict:
    cp = subprocess.run(["./run.sh", "--diag", "--json"], capture_output=True, text=True)
    assert cp.returncode == 0, f"diag failed: {cp.stderr or cp.stdout}"
    return json.loads(cp.stdout)


def test_diag_json_valid():
    data = _run_diag_json()
    assert isinstance(data, dict)


def test_diag_has_minimum_sections():
    data = _run_diag_json()
    for key in ("timings", "import_smells", "io_hotspots", "fast_wins"):
        assert key in data, f"missing section: {key}"


def test_no_core_androguard_smells():
    data = _run_diag_json()
    smells_blob = " ".join(data.get("import_smells", []))
    assert "scytaledroid.StaticAnalysis.core._androguard" not in smells_blob
    assert "from . _androguard import" not in smells_blob.replace("  ", " ")
