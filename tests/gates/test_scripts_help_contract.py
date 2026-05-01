from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = [pytest.mark.gate, pytest.mark.tier3]


def _script_paths() -> list[Path]:
    return sorted(path for path in Path("scripts").rglob("*.py") if "__pycache__" not in path.parts)


@pytest.mark.parametrize("script_path", _script_paths(), ids=lambda path: str(path))
def test_python_scripts_have_safe_help(script_path: Path) -> None:
    """Every Python helper script should support safe, side-effect-free discovery."""

    proc = subprocess.run(
        [sys.executable, str(script_path), "--help"],
        text=True,
        capture_output=True,
        timeout=8,
        check=False,
    )
    output = (proc.stdout or proc.stderr).strip()
    assert proc.returncode == 0, output
    assert output.lower().startswith("usage:"), output[:500]
