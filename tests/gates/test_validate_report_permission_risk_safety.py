from __future__ import annotations

import subprocess
import sys

import pytest

pytestmark = [pytest.mark.gate, pytest.mark.tier3]


def test_validate_report_permission_risk_help_documents_safety_flags() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/static_analysis/validate_report_permission_risk.py", "--help"],
        text=True,
        capture_output=True,
        timeout=12,
        check=False,
    )
    out = (proc.stdout or proc.stderr).lower()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "--write-live" in out
    assert "--prune-vnext-rows" in out
    assert "dry-run" in out or "no db writes" in out
