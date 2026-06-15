from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scytaledroid.Database.db_utils import artifact_registry_dynamic_prune as prune


def _row(*, artifact_id: int, run_id: str, host_path: str, primary_reason: str = "truly_detached") -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "run_type": "dynamic",
        "run_id": run_id,
        "dynamic_run_id": run_id,
        "resolved_dynamic_run_id": run_id,
        "artifact_type": "dynamic_run_manifest",
        "host_path": host_path,
        "host_workspace_prefix": "/old/root",
        "host_path_exists": False,
        "created_at_utc": "2026-02-08 00:00:00",
        "status_reason": None,
        "has_dynamic_session": False,
        "has_any_dynamic_db_reference": False,
        "primary_reason": primary_reason,
        "malformed_dynamic_run_id": False,
        "unknown_needs_review": False,
    }


def test_help_is_safe_without_pythonpath() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "prune_artifact_registry_dynamic_detached.py"
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
    assert "dynamic" in out


def test_build_dynamic_prune_proposal(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        prune,
        "collect_artifact_registry_dynamic_dangling_report",
        lambda run_sql, repo_root: {  # noqa: ARG005
            "dynamic_dangling_rows": [
                _row(artifact_id=1, run_id="11111111-1111-4111-8111-111111111111", host_path=str(tmp_path / "a")),
                _row(artifact_id=2, run_id="22222222-2222-4222-8222-222222222222", host_path=str(tmp_path / "b")),
            ]
        },
    )
    counts = {
        "artifact_registry_dynamic_prune.total_count": {"c": 100},
        "artifact_registry_dynamic_prune.dynamic_dangling_count": {"c": 2},
        "artifact_registry_dynamic_prune.static_dangling_count": {"c": 50},
    }

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=True, query_name=None):  # noqa: ANN001,ARG001
        return counts[query_name]

    proposal = prune.build_dynamic_prune_proposal(fake_run_sql, repo_root=tmp_path, expected_count=2, expected_run_count=2)
    assert proposal.targeted_row_count == 2
    assert proposal.targeted_distinct_dynamic_run_ids == 2
    assert proposal.all_truly_detached is True
    assert proposal.all_missing_dynamic_sessions is True
    assert proposal.all_missing_dynamic_db_refs is True
    assert proposal.all_target_files_missing is True


def test_validate_dynamic_prune_proposal_rejects_non_exact_counts() -> None:
    proposal = prune.DynamicPruneProposal(
        total_rows_before=10,
        dynamic_dangling_before=1,
        static_dangling_before=2,
        targeted_row_count=1,
        targeted_distinct_dynamic_run_ids=1,
        targeted_run_ids=("r1",),
        targeted_artifact_ids=(1,),
        reason_counts={"truly_detached": 1},
        artifact_type_counts={"dynamic_run_manifest": 1},
        path_root_counts={"/old/root": 1},
        oldest_created_at_utc=None,
        newest_created_at_utc=None,
        all_truly_detached=True,
        all_dynamic_run_id_populated=True,
        all_missing_dynamic_sessions=True,
        all_missing_dynamic_db_refs=True,
        all_target_files_missing=True,
        malformed_dynamic_run_id_count=0,
        unknown_needs_review_count=0,
        sample_rows=(),
        target_rows=(),
        exact_sql_predicate="x",
        apply_delete_sql="y",
        expected_count_match=False,
        expected_run_count_match=False,
    )
    with pytest.raises(ValueError, match="expected 750"):
        prune.validate_dynamic_prune_proposal(proposal, expected_count=750, expected_run_count=30)


def test_write_dynamic_prune_receipts(tmp_path: Path) -> None:
    proposal = prune.DynamicPruneProposal(
        total_rows_before=100,
        dynamic_dangling_before=2,
        static_dangling_before=10,
        targeted_row_count=2,
        targeted_distinct_dynamic_run_ids=1,
        targeted_run_ids=("11111111-1111-4111-8111-111111111111",),
        targeted_artifact_ids=(1, 2),
        reason_counts={"truly_detached": 2},
        artifact_type_counts={"dynamic_run_manifest": 2},
        path_root_counts={"/old/root": 2},
        oldest_created_at_utc="2026-02-08 00:00:00",
        newest_created_at_utc="2026-02-08 00:00:00",
        all_truly_detached=True,
        all_dynamic_run_id_populated=True,
        all_missing_dynamic_sessions=True,
        all_missing_dynamic_db_refs=True,
        all_target_files_missing=True,
        malformed_dynamic_run_id_count=0,
        unknown_needs_review_count=0,
        sample_rows=({"artifact_id": 1},),
        target_rows=({"artifact_id": 1, "resolved_dynamic_run_id": "11111111-1111-4111-8111-111111111111"},),
        exact_sql_predicate="x",
        apply_delete_sql="y",
        expected_count_match=True,
        expected_run_count_match=True,
    )
    prune.write_dynamic_prune_receipts(tmp_path, stem="artifact_registry_dynamic_prune_test", proposal=proposal, apply_requested=False)
    assert (tmp_path / "artifact_registry_dynamic_prune_test.json").is_file()
    assert (tmp_path / "artifact_registry_dynamic_prune_test.csv").is_file()
    assert (tmp_path / "artifact_registry_dynamic_prune_test.sql").is_file()
    assert (tmp_path / "artifact_registry_dynamic_prune_run_ids_test.txt").is_file()
    payload = json.loads((tmp_path / "artifact_registry_dynamic_prune_test.json").read_text(encoding="utf-8"))
    assert payload["format"] == "scytaledroid.artifact_registry_dynamic_prune_receipt.v1"
    assert payload["meta"]["targeted_row_count"] == 2
