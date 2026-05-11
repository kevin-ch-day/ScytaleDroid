"""Smoke: ``verify_evidence_manifest.py`` CLI."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_verify_evidence_manifest_help_exits_zero() -> None:
    repo = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo)
    proc = subprocess.run(
        [sys.executable, str(repo / "scripts" / "db" / "verify_evidence_manifest.py"), "--help"],
        cwd=str(repo),
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "--session" in (proc.stdout or "").lower() or "--session" in (proc.stderr or "").lower()
