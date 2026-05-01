"""Lightweight sanity for scripts/db tooling (no DB required)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_recreate_web_consumer_views_dry_run_list() -> None:
    script = REPO_ROOT / "scripts/db/recreate_web_consumer_views.py"
    proc = subprocess.run(
        [sys.executable, str(script), "recreate", "--dry-run"],
        cwd=str(REPO_ROOT),
        env={**__import__("os").environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "v_web_app_directory" in proc.stdout


def test_check_schema_posture_sql_exists() -> None:
    sql = REPO_ROOT / "scripts/db/check_schema_posture.sql"
    assert sql.exists()
    body = sql.read_text(encoding="utf-8")
    assert "information_schema.TABLES" in body


def test_smoke_shell_script_readable() -> None:
    shell = REPO_ROOT / "scripts/db/smoke_web_db.sh"
    assert shell.exists()
    text = shell.read_text(encoding="utf-8")
    assert "sd_web_db_smoke.php" in text
