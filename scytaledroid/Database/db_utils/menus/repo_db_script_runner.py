"""Run ``scripts/db/*.py`` helpers from menus with repo-root ``PYTHONPATH``."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import status_messages


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def run_scripts_db_py(script_name: str, extra: list[str] | None = None) -> int:
    """Execute ``python scripts/db/<script_name>`` from repo root; return process exit code."""

    script_name = Path(str(script_name or "")).name
    root = repo_root()
    scripts_dir = (root / "scripts" / "db").resolve()
    script = (scripts_dir / script_name).resolve()
    if not script.is_file() or not script.is_relative_to(scripts_dir):
        print(status_messages.status(f"Missing script: {script}", level="error"))
        return 1
    cmd = [sys.executable, str(script), *(extra or [])]
    env = {**os.environ, "PYTHONPATH": str(root)}
    print(status_messages.status(f"Running: {' '.join(cmd)} (cwd={root})", level="info"))
    proc = subprocess.run(cmd, cwd=str(root), env=env)
    return int(proc.returncode)


__all__ = ["repo_root", "run_scripts_db_py"]
