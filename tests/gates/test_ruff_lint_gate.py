from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_repo_python_files_pass_ruff() -> None:
    """Keep the repository-wide Ruff baseline enforced outside CI as well."""

    root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        (sys.executable, "-m", "ruff", "check", "scytaledroid", "scripts", "tests"),
        cwd=root,
        check=False,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
