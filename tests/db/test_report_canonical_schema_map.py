from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_report_canonical_schema_map_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_canonical_schema_map.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (proc.stdout or "").lower().startswith("usage:")
