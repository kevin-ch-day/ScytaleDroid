from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scytaledroid.Database.db_utils import artifact_registry_static_session_prune as prune


def test_help_is_safe_without_pythonpath() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "prune_artifact_registry_static_legacy_sessions.py"
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
    assert "session-stamp" in out


def test_build_static_session_prune_proposal(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        prune,
        "collect_static_session_retirement_report",
        lambda run_sql, repo_root: {  # noqa: ARG005
            "legacy_session_retirement_sessions": [
                {
                    "session_stamp": "20260429-all-full",
                    "recommended_action": "candidate_small_session_retirement_review",
                    "legacy_payload_total_rows": 35,
                },
                {
                    "session_stamp": "phase4a-closeout-smoke",
                    "recommended_action": "blocked_file_present_review",
                    "legacy_payload_total_rows": 738,
                },
            ],
            "legacy_session_retirement_runs": [
                {"session_stamp": "20260429-all-full", "run_id": 971},
                {"session_stamp": "phase4a-closeout-smoke", "run_id": 1200},
            ],
            "_dangling_rows": [
                {
                    "artifact_id": 1,
                    "session_stamp": "20260429-all-full",
                    "resolved_static_run_id": 971,
                    "package": "android.autoinstalls.config.motorola.layout",
                    "primary_reason": "legacy_mirror_only_file_missing",
                    "artifact_type": "static_report",
                    "host_path_family": "static_reports_latest",
                    "host_path_exists": False,
                    "canonical_db_reference_present": False,
                    "created_at_utc": "2026-02-08 00:00:00",
                    "host_path": str(tmp_path / "a"),
                },
                {
                    "artifact_id": 2,
                    "session_stamp": "phase4a-closeout-smoke",
                    "resolved_static_run_id": 1200,
                    "package": "com.example.blocked",
                    "primary_reason": "legacy_mirror_only_with_file",
                    "artifact_type": "dep_snapshot",
                    "host_path_family": "dep_snapshot",
                    "host_path_exists": True,
                    "canonical_db_reference_present": False,
                    "created_at_utc": "2026-02-08 00:00:01",
                    "host_path": str(tmp_path / "b"),
                },
            ],
        },
    )
    counts = {
        "artifact_registry_static_prune.total_count": {"c": 100},
        "artifact_registry_static_prune.static_dangling_count": {"c": 10},
        "artifact_registry_static_prune.dynamic_dangling_count": {"c": 5},
    }

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=True, query_name=None):  # noqa: ANN001,ARG001
        return counts[query_name]

    proposal = prune.build_static_session_prune_proposal(
        fake_run_sql,
        repo_root=tmp_path,
        session_stamps=["20260429-all-full"],
        expected_count=1,
    )
    assert proposal.targeted_row_count == 1
    assert proposal.targeted_session_stamps == ("20260429-all-full",)
    assert proposal.file_present_count == 0
    assert proposal.legacy_payload_total_rows == 35
    assert proposal.expected_count_match is True


def test_validate_static_session_prune_proposal_rejects_blocked_session() -> None:
    proposal = prune.StaticSessionPruneProposal(
        total_rows_before=100,
        static_dangling_before=10,
        dynamic_dangling_before=5,
        targeted_row_count=1,
        targeted_session_count=1,
        targeted_run_count=1,
        targeted_artifact_ids=(1,),
        targeted_static_run_ids=(971,),
        targeted_session_stamps=("phase4a-closeout-smoke",),
        candidate_actions={"phase4a-closeout-smoke": "blocked_file_present_review"},
        reason_counts={"legacy_mirror_only_with_file": 1},
        artifact_type_counts={"static_report": 1},
        path_family_counts={"static_reports_latest": 1},
        legacy_payload_total_rows=738,
        file_present_count=1,
        file_missing_count=0,
        canonical_db_residue_count=0,
        malformed_or_unknown_count=0,
        oldest_created_at_utc=None,
        newest_created_at_utc=None,
        target_rows=(),
        sample_rows=(),
        exact_sql_predicate="x",
        apply_delete_sql="y",
        expected_count_match=None,
    )
    with pytest.raises(ValueError, match="not candidate retirement sessions"):
        prune.validate_static_session_prune_proposal(proposal)


def test_write_static_session_prune_receipts(tmp_path: Path) -> None:
    proposal = prune.StaticSessionPruneProposal(
        total_rows_before=100,
        static_dangling_before=10,
        dynamic_dangling_before=5,
        targeted_row_count=1,
        targeted_session_count=1,
        targeted_run_count=1,
        targeted_artifact_ids=(1,),
        targeted_static_run_ids=(971,),
        targeted_session_stamps=("20260429-all-full",),
        candidate_actions={"20260429-all-full": "candidate_small_session_retirement_review"},
        reason_counts={"legacy_mirror_only_file_missing": 1},
        artifact_type_counts={"static_report": 1},
        path_family_counts={"static_reports_latest": 1},
        legacy_payload_total_rows=35,
        file_present_count=0,
        file_missing_count=1,
        canonical_db_residue_count=0,
        malformed_or_unknown_count=0,
        oldest_created_at_utc="2026-02-08 00:00:00",
        newest_created_at_utc="2026-02-08 00:00:00",
        target_rows=({"artifact_id": 1, "session_stamp": "20260429-all-full"},),
        sample_rows=({"artifact_id": 1},),
        exact_sql_predicate="x",
        apply_delete_sql="y",
        expected_count_match=True,
    )
    prune.write_static_session_prune_receipts(
        tmp_path,
        stem="artifact_registry_static_session_prune_test",
        proposal=proposal,
        apply_requested=False,
    )
    assert (tmp_path / "artifact_registry_static_session_prune_test.json").is_file()
    assert (tmp_path / "artifact_registry_static_session_prune_test.csv").is_file()
    assert (tmp_path / "artifact_registry_static_session_prune_test.sql").is_file()
    assert (tmp_path / "artifact_registry_static_session_prune_sessions_test.txt").is_file()
    payload = json.loads((tmp_path / "artifact_registry_static_session_prune_test.json").read_text(encoding="utf-8"))
    assert payload["format"] == "scytaledroid.artifact_registry_static_session_prune_receipt.v1"
    assert payload["meta"]["targeted_session_stamps"] == ["20260429-all-full"]
