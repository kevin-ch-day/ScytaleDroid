from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.gate, pytest.mark.tier3]


def test_run_artifact_map_help_lists_output_modes() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/static_analysis/run_artifact_map.py", "--help"],
        text=True,
        capture_output=True,
        timeout=12,
        check=False,
    )
    out = (proc.stdout or proc.stderr).lower()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "--session" in out
    assert "--json" in out
    assert "--write-report" in out
    assert "--no-db" in out
    assert "--strict" in out
    assert "--strict-log-duplicates" in out
    assert "--include-harvest-linkage" in out
    assert "--include-harvest-receipt-linkage" in out


def test_run_artifact_map_omitting_strict_does_not_crash() -> None:
    """Regression: main() must not reference args.strict without a defined argparse flag."""

    repo = Path(__file__).resolve().parents[2]
    env = {**os.environ, "PYTHONPATH": str(repo)}
    proc = subprocess.run(
        [
            sys.executable,
            str(repo / "scripts/static_analysis/run_artifact_map.py"),
            "--session",
            "fake-session",
        ],
        cwd=str(repo),
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    assert "AttributeError" not in combined, combined
    assert "has no attribute 'strict'" not in combined, combined
