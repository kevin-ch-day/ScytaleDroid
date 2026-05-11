from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.gate, pytest.mark.tier3]


def test_static_schema_audit_help_exits_zero() -> None:
    repo = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [sys.executable, str(repo / "scripts" / "db" / "static_schema_audit.py"), "--help"],
        cwd=str(repo),
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = (proc.stdout or "").lower()
    assert "--json" in out
    assert "read-only" in out or "schema" in out
