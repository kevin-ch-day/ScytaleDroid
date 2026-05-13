"""CLI contract for report_dynamic_static_alignment.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_static_alignment as report


class _FakeCoreQ:
    def run_sql(self, sql, params=(), **kwargs):  # noqa: ANN001, ANN201
        table = params[0]
        if table == "dynamic_sessions":
            return [
                {
                    "index_name": "ix_dynamic_sessions_base_apk_sha256",
                    "column_name": "base_apk_sha256",
                }
            ]
        if table == "static_analysis_runs":
            return [
                {"index_name": "ix_static_runs_base_hash_contract", "column_name": "base_apk_sha256"},
                {"index_name": "ix_static_runs_base_hash_contract", "column_name": "status"},
                {"index_name": "ix_static_runs_base_hash_contract", "column_name": "run_class"},
                {"index_name": "ix_static_runs_base_hash_contract", "column_name": "identity_valid"},
            ]
        return []


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_static_alignment.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "dynamic" in out or "static" in out
    assert "--exact-target-readiness" in out


def test_apk_lineage_availability_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_apk_lineage_availability.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "--only-gaps" in out
    assert "--design-checks" in out
    assert "lineage" in out


def test_package_lineage_coverage_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_package_lineage_coverage.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "--design-checks" in out
    assert "--drift-details" in out
    assert "install-set" in out


def test_dynamic_static_recovery_plan_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_static_recovery_plan.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "recovery" in out
    assert "--package" in out


def test_static_analysis_targets_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_static_analysis_targets.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "--only-actionable" in out
    assert "target queue" in out


def test_backfill_apk_sets_from_receipts_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "backfill_apk_sets_from_receipts.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "--apply" in out
    assert "install-set" in out


def test_backfill_apk_set_links_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "backfill_apk_set_links.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "--apply" in out
    assert "apk_set_id" in out


def test_index_posture_accepts_static_composite_as_base_hash_coverage() -> None:
    posture = report._index_posture(_FakeCoreQ())
    assert posture["dynamic_sessions_base_apk_sha256_index_present"] == 1
    assert posture["static_runs_base_hash_contract_index_present"] == 1
    assert posture["static_runs_base_apk_sha256_index_covered"] == 1
