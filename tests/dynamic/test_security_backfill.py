from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.security_backfill import backfill_security_surface_cohort


def test_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "backfill_dynamic_security_surface.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("usage:")


def test_backfill_dry_run_skips_missing_report(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-1",
                "run_manifest_version": 1,
                "created_at": "2026-07-02T00:00:00Z",
                "target": {"package_name": "com.example.app"},
                "artifacts": [],
            }
        ),
        encoding="utf-8",
    )

    summary = backfill_security_surface_cohort(tmp_path, apply=False)

    assert summary.scanned == 1
    assert summary.skipped == 1
    assert summary.rows[0].reason == "missing_pcap_report"
