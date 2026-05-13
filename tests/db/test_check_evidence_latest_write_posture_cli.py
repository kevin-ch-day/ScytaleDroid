"""CLI contract for check_evidence_latest_write_posture.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "check_evidence_latest_write_posture.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "since-hours" in out or "since_hours" in out.replace("-", "_")
