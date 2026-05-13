"""Tests for read-only artifact registry cleanup candidate report."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import pytest

from scytaledroid.Database.db_utils.artifact_registry_cleanup_report import (
    CATEGORY_ACTIONS,
    collect_cleanup_candidate_report,
    format_text_report,
)


def test_format_text_report_includes_sections() -> None:
    data = {
        "recent_days_window": 7,
        "old_days_threshold": 90,
        "run_type_filter": None,
        "totals_by_category": [
            {
                "cleanup_category": "linked_keep",
                "row_count": 100,
                "candidate_action": CATEGORY_ACTIONS["linked_keep"],
            },
            {
                "cleanup_category": "dangling_db_only_candidate",
                "row_count": 5,
                "candidate_action": CATEGORY_ACTIONS["dangling_db_only_candidate"],
            },
        ],
        "summary_dimensions": [
            {
                "cleanup_category": "dangling_db_only_candidate",
                "run_type": "static",
                "link_state": "dangling_static_run",
                "artifact_type": "dep_snapshot",
                "age_bucket": "90d+",
                "host_path_presence": "blank_host",
                "static_run_id_shape": "numeric_run_id",
                "row_count": 5,
                "created_min": None,
                "created_max": None,
            }
        ],
        "top_run_ids_by_category": {
            "dangling_db_only_candidate": [{"run_id": "42", "count": 5}],
        },
        "path_probe": None,
    }
    text = format_text_report(data)
    assert "cleanup candidates (read-only)" in text
    assert "linked_keep" in text
    assert "dangling_db_only_candidate" in text
    assert "dep_snapshot" in text
    assert "42\t5" in text
    assert "prune_artifact_registry_dangling.py" in text


def test_collect_cleanup_candidate_report_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    returns: list[list[dict[str, object]]] = [
        [
            {
                "cleanup_category": "linked_keep",
                "run_type": "static",
                "link_state": "linked",
                "artifact_type": "static_report",
                "age_bucket": "0-7d",
                "host_path_presence": "host_path_set",
                "static_run_id_shape": "numeric_run_id",
                "row_count": 3,
                "created_min": None,
                "created_max": None,
            }
        ],
        [{"cleanup_category": "linked_keep", "run_id": "1", "cnt": 3}],
        [{"cleanup_category": "linked_keep", "row_count": 3}],
    ]

    def fake_run_sql(_sql: str, _params=None, **_kw):
        if not returns:
            return []
        return returns.pop(0)

    out = collect_cleanup_candidate_report(fake_run_sql, path_sample_limit=0)
    assert out["totals_by_category"][0]["row_count"] == 3
    assert out["summary_dimensions"][0]["artifact_type"] == "static_report"
    assert out["path_probe"] is None
    assert out["top_run_ids_by_category"]["linked_keep"][0]["run_id"] == "1"


def test_collect_cleanup_candidate_report_path_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    returns: list[list[dict[str, object]]] = [
        [],
        [],
        [],
        [
            {
                "artifact_id": 9,
                "cleanup_category": "dangling_old_export_first",
                "run_type": "static",
                "host_path": "/no/such/file/for_probe_test_artifact_registry",
            }
        ],
    ]

    def fake_run_sql(_sql: str, _params=None, **_kw):
        if not returns:
            return []
        return returns.pop(0)

    out = collect_cleanup_candidate_report(fake_run_sql, path_sample_limit=5)
    assert out["path_probe"] is not None
    assert out["path_probe"]["sampled_rows"] == 1
    assert out["path_probe"]["host_path_exists_false"] >= 1


def test_script_help_is_safe_without_pythonpath() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_artifact_registry_cleanup_candidates.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or proc.stderr).strip().lower()
    assert out.startswith("usage:")
