"""CLI contract for verify_static_session_id_rollout.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_help_lists_explain_flag() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "verify_static_session_id_rollout.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "--explain" in out
