from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scytaledroid.Database.db_utils import artifact_registry_static_file_present_review_prune as subject


def test_help_is_safe_without_pythonpath(assert_safe_script_help) -> None:
    out = assert_safe_script_help(
        "scripts/db/prune_artifact_registry_static_file_present_reviewed.py"
    ).lower()
    assert out.startswith("usage:")
    assert "--apply" in out
    assert "--expected-count" in out
    assert "--allow-prior-version-retention-review" in out


def test_build_review_prune_proposal_filters_selected_review_classes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        subject,
        "collect_static_file_present_detached_report",
        lambda run_sql, repo_root: {  # noqa: ARG005
            "file_present_detached_rows": [
                {
                    "artifact_id": 10,
                    "resolved_static_run_id": 100,
                    "artifact_type": "static_report",
                    "host_path_family": "static_reports_latest",
                    "host_path_exists": True,
                    "primary_reason": "file_present_db_detached",
                    "missing_static_run": True,
                    "inferred_package_name": "com.example.alpha",
                    "canonical_coverage_class": "SUPERSEDED_BY_NEWER_CANONICAL_VERSION",
                    "staged_review_action": subject.PRIOR_VERSION_ACTION,
                    "created_at_utc": "2026-06-01 10:00:00",
                    "host_path": str(tmp_path / "alpha.json"),
                },
                {
                    "artifact_id": 11,
                    "resolved_static_run_id": 101,
                    "artifact_type": "manifest_evidence",
                    "host_path_family": "manifest_evidence",
                    "host_path_exists": True,
                    "primary_reason": "file_present_db_detached",
                    "missing_static_run": True,
                    "inferred_package_name": "com.example.beta",
                    "canonical_coverage_class": "PACKAGE_HAS_CANONICAL_DIFFERENT_VERSION",
                    "staged_review_action": subject.IDENTITY_GAP_ACTION,
                    "created_at_utc": "2026-06-02 10:00:00",
                    "host_path": str(tmp_path / "beta.json"),
                },
                {
                    "artifact_id": 12,
                    "resolved_static_run_id": 102,
                    "artifact_type": "static_report",
                    "host_path_family": "static_reports_latest",
                    "host_path_exists": True,
                    "primary_reason": "file_present_db_detached",
                    "missing_static_run": True,
                    "inferred_package_name": "com.example.gamma",
                    "canonical_coverage_class": "SUPERSEDED_BY_NEWER_CANONICAL_VERSION",
                    "staged_review_action": subject.PRIOR_VERSION_ACTION,
                    "created_at_utc": "2026-07-09 10:00:00",
                    "host_path": str(tmp_path / "gamma.json"),
                },
            ]
        },
    )

    def fake_run_sql(_sql: str, _params=(), **kwargs):
        if kwargs.get("query_name") == "artifact_registry_static_file_present_review_prune.total_count":
            return {"c": 100}
        if kwargs.get("query_name") == "artifact_registry_static_file_present_review_prune.static_dangling_count":
            return {"c": 3}
        raise AssertionError(f"unexpected query_name: {kwargs.get('query_name')}")

    proposal = subject.build_static_file_present_review_prune_proposal(
        fake_run_sql,
        repo_root=tmp_path,
        allow_prior_version=True,
        allow_identity_gap=True,
        min_age_days=30,
        expected_count=2,
        now_utc=datetime(2026, 7, 10, tzinfo=UTC),
    )
    assert proposal.targeted_row_count == 2
    assert proposal.targeted_artifact_ids == (10, 11)
    assert proposal.targeted_static_run_ids == (100, 101)
    assert proposal.staged_action_counts == {
        subject.IDENTITY_GAP_ACTION: 1,
        subject.PRIOR_VERSION_ACTION: 1,
    }
    assert proposal.all_host_files_present is True
    assert proposal.all_file_present_detached is True
    assert proposal.all_action_coverage_consistent is True
    assert proposal.all_missing_static_run is True
    subject.validate_static_file_present_review_prune_proposal(proposal, expected_count=2)


def test_validate_review_prune_blocks_unselected_actions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        subject,
        "collect_static_file_present_detached_report",
        lambda run_sql, repo_root: {"file_present_detached_rows": []},  # noqa: ARG005
    )

    def fake_run_sql(_sql: str, _params=(), **kwargs):
        if kwargs.get("query_name") == "artifact_registry_static_file_present_review_prune.total_count":
            return {"c": 100}
        if kwargs.get("query_name") == "artifact_registry_static_file_present_review_prune.static_dangling_count":
            return {"c": 3}
        return {"c": 0}

    proposal = subject.build_static_file_present_review_prune_proposal(fake_run_sql, repo_root=tmp_path)
    with pytest.raises(ValueError, match="no reviewed file-present staged actions"):
        subject.validate_static_file_present_review_prune_proposal(proposal)


def test_write_review_prune_receipts(tmp_path: Path) -> None:
    proposal = subject.StaticFilePresentReviewPruneProposal(
        total_rows_before=100,
        static_dangling_before=2,
        targeted_row_count=1,
        targeted_distinct_static_run_ids=1,
        targeted_distinct_packages=1,
        targeted_artifact_ids=(10,),
        targeted_static_run_ids=(100,),
        selected_staged_actions=(subject.PRIOR_VERSION_ACTION,),
        min_age_days=30,
        cutoff_utc="2026-06-10 00:00:00",
        artifact_type_counts={"static_report": 1},
        path_family_counts={"static_reports_latest": 1},
        package_counts={"com.example.alpha": 1},
        staged_action_counts={subject.PRIOR_VERSION_ACTION: 1},
        coverage_class_counts={"SUPERSEDED_BY_NEWER_CANONICAL_VERSION": 1},
        oldest_created_at_utc="2026-06-01 10:00:00",
        newest_created_at_utc="2026-06-01 10:00:00",
        all_host_files_present=True,
        all_file_present_detached=True,
        all_action_coverage_consistent=True,
        all_missing_static_run=True,
        all_older_than_cutoff=True,
        expected_count_match=True,
        sample_rows=({"artifact_id": 10},),
        target_rows=({"artifact_id": 10},),
        exact_sql_predicate="test predicate",
        apply_delete_sql="DELETE FROM artifact_registry WHERE artifact_id IN (<targeted artifact_id set>)",
    )
    paths = subject.write_static_file_present_review_prune_receipts(
        tmp_path,
        stem="artifact_registry_static_file_present_review_prune_test",
        proposal=proposal,
        apply_requested=False,
        apply_result=None,
    )
    for value in paths.values():
        assert Path(value).is_file()
    payload = json.loads(
        (tmp_path / "artifact_registry_static_file_present_review_prune_test.json").read_text(encoding="utf-8")
    )
    assert payload["format"] == "scytaledroid.artifact_registry_static_file_present_review_prune_receipt.v1"
    assert payload["meta"]["targeted_row_count"] == 1
    sql = (tmp_path / "artifact_registry_static_file_present_review_prune_test.sql").read_text(encoding="utf-8")
    assert "DELETE FROM artifact_registry" in sql
