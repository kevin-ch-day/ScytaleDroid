"""CLI contract for normalize_evidence_hash_collation.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.db import normalize_evidence_hash_collation as migration


def test_help_lists_script() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "normalize_evidence_hash_collation.py"
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
    assert "--apply" in out


def test_target_ok_requires_ascii_bin_and_expected_nullability() -> None:
    row = {
        "column_type": "char(64)",
        "character_set_name": "ascii",
        "collation_name": "ascii_bin",
        "is_nullable": "YES",
    }
    assert migration._target_ok(row, nullable="YES")
    assert not migration._target_ok(row, nullable="NO")


def test_target_ok_rejects_legacy_collation() -> None:
    row = {
        "column_type": "char(64)",
        "character_set_name": "latin1",
        "collation_name": "latin1_swedish_ci",
        "is_nullable": "NO",
    }
    assert not migration._target_ok(row, nullable="NO")
