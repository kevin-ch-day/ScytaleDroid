from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def assert_safe_script_help():
    repo = Path(__file__).resolve().parents[2]

    def _run(script_relpath: str | Path, *args: str, timeout: int = 20) -> str:
        script = script_relpath if isinstance(script_relpath, Path) else repo / script_relpath
        proc = subprocess.run(
            [sys.executable, str(script), *args, "--help"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        output = proc.stdout or proc.stderr
        assert output.strip().lower().startswith("usage:"), output[:500]
        return output

    return _run
