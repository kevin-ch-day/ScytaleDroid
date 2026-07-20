"""Regression coverage for repository launcher behavior."""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_launch_scripts_have_valid_bash_syntax() -> None:
    for script in ("run.sh", "setup.sh"):
        result = subprocess.run(
            ["bash", "-n", str(REPO_ROOT / script)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


def test_run_script_is_cwd_independent_and_exposes_new_system_check(tmp_path: Path) -> None:
    result = subprocess.run(
        [str(REPO_ROOT / "run.sh"), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert "--new-system-check" in result.stdout
