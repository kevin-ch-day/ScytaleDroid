from __future__ import annotations

from pathlib import Path

import pytest


pytestmark = [pytest.mark.contract, pytest.mark.gate]

ROOT = Path(__file__).resolve().parents[2]

STALE_TEST_REFS = {
    "tests/db_utils": "tests/database",
    "tests/static/test_static_batch_summary.py": "tests/static_analysis/test_batch_log_semantics.py",
    "tests/static/test_static_views.py": "tests/static_analysis/test_scan_view_cards.py",
    "tests/static/test_permission_risk_static_run_id.py": "tests/persistence/test_permission_risk.py",
    "tests/ui/test_global_menu_rollout.py": "tests/ui/test_database_menu_rollout.py or peer split files",
    "tests/test_inventory_summary.py": "tests/inventory/test_inventory_views.py",
    "tests/test_inventory_status.py": "tests/inventory/test_status.py",
    "tests/test_inventory_guard_state.py": "tests/inventory/test_guard_state.py",
    "tests/test_db_paramstyle.py": "tests/database/test_db_posture_pr4b.py",
    "tests/test_main_db_maintenance.py": "tests/database/test_main_db_maintenance.py",
}


def _candidate_files() -> list[Path]:
    files = [ROOT / "AGENTS.md"]
    files.extend((ROOT / "docs").rglob("*.md"))
    files.extend((ROOT / "scripts").rglob("*.py"))
    return [path for path in files if path.is_file()]


def test_docs_and_scripts_do_not_reference_retired_test_paths() -> None:
    hits: list[str] = []
    for path in _candidate_files():
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(ROOT)
        for stale, replacement in STALE_TEST_REFS.items():
            if stale not in text:
                continue
            hits.append(f"{rel}: replace {stale} -> {replacement}")
    assert not hits, "stale test references found:\n" + "\n".join(sorted(hits))
