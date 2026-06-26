from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests._collection_policy import derived_markers_for_path


pytestmark = [pytest.mark.contract, pytest.mark.gate]


def test_collection_policy_marks_gate_files() -> None:
    assert derived_markers_for_path("tests/gates/test_phase1_ui_contract.py") == (
        "contract",
        "gate",
    )


def test_collection_policy_marks_ui_files() -> None:
    assert derived_markers_for_path("tests/ui/test_dynamic_menu_rollout.py") == (
        "contract",
        "ui_contract",
    )


def test_collection_policy_marks_unit_and_integration_files() -> None:
    assert derived_markers_for_path("tests/unit/test_operational_risk.py") == ("unit",)
    assert derived_markers_for_path("tests/integration/test_persist_run_summary.py") == (
        "integration",
    )


def test_collection_policy_marks_db_report_files() -> None:
    assert derived_markers_for_path("tests/db/test_report_dynamic_deep_audit.py") == (
        "report_contract",
    )


def test_collection_policy_leaves_plain_domain_files_unmarked() -> None:
    assert derived_markers_for_path("tests/dynamic/test_menu_selection.py") == ()
    assert derived_markers_for_path("tests/database/test_schema_gate_static.py") == ()


def _run_pytest(*args: str) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[2]
    return subprocess.run(
        [sys.executable, "-m", "pytest", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_marker_selection_smoke_for_unit_bucket() -> None:
    proc = _run_pytest("tests/unit/test_operational_risk.py", "-m", "unit", "-q")
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout or ""
    assert "3 passed" in out
    assert "deselected" not in out


def test_marker_selection_smoke_for_integration_bucket() -> None:
    proc = _run_pytest("tests/integration/test_persist_run_summary.py", "-m", "integration", "-q")
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout or ""
    assert "deselected" not in out
    assert any(token in out for token in ("passed", "skipped"))
