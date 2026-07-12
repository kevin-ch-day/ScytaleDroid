from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.Database.db_utils import artifact_registry_static_file_present_resolution as subject


def test_help_is_safe_without_pythonpath(assert_safe_script_help) -> None:
    out = assert_safe_script_help(
        "scripts/db/prune_artifact_registry_static_file_present_resolved.py"
    ).lower()
    assert out.startswith("usage:")
    assert "--apply" in out
    assert "--expected-count" in out


def test_build_static_file_present_resolution_proposal_filters_exact_hash_rows(
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
                    "inferred_package_name": "com.example.alpha",
                    "canonical_match_static_run_id": 900,
                    "canonical_coverage_class": subject.TARGET_COVERAGE_CLASS,
                    "staged_review_action": subject.TARGET_STAGED_ACTION,
                    "registry_resolution_candidate": True,
                    "created_at_utc": "2026-07-09 10:00:00",
                    "host_path": str(tmp_path / "alpha.json"),
                },
                {
                    "artifact_id": 11,
                    "resolved_static_run_id": 101,
                    "artifact_type": "static_report",
                    "host_path_family": "static_reports_latest",
                    "host_path_exists": True,
                    "inferred_package_name": "com.example.beta",
                    "canonical_match_static_run_id": 901,
                    "canonical_coverage_class": "SUPERSEDED_BY_NEWER_CANONICAL_VERSION",
                    "staged_review_action": "STAGE_PRIOR_VERSION_RETENTION_REVIEW",
                    "registry_resolution_candidate": False,
                    "created_at_utc": "2026-07-09 10:01:00",
                    "host_path": str(tmp_path / "beta.json"),
                },
            ]
        },
    )

    def fake_run_sql(_sql: str, _params=(), **kwargs):
        if kwargs.get("query_name") == "artifact_registry_static_file_present_resolution.total_count":
            return {"c": 100}
        if kwargs.get("query_name") == "artifact_registry_static_file_present_resolution.static_dangling_count":
            return {"c": 5}
        raise AssertionError(f"unexpected query_name: {kwargs.get('query_name')}")

    proposal = subject.build_static_file_present_resolution_proposal(
        fake_run_sql,
        repo_root=tmp_path,
        expected_count=1,
    )
    assert proposal.targeted_row_count == 1
    assert proposal.targeted_artifact_ids == (10,)
    assert proposal.targeted_static_run_ids == (100,)
    assert proposal.targeted_distinct_packages == 1
    assert proposal.expected_count_match is True
    assert proposal.all_host_files_present is True
    assert proposal.all_same_hash_covered is True
    assert proposal.all_have_canonical_match is True
    subject.validate_static_file_present_resolution_proposal(proposal, expected_count=1)


def test_validate_static_file_present_resolution_proposal_blocks_count_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        subject,
        "collect_static_file_present_detached_report",
        lambda run_sql, repo_root: {"file_present_detached_rows": []},  # noqa: ARG005
    )

    def fake_run_sql(_sql: str, _params=(), **kwargs):
        if kwargs.get("query_name") == "artifact_registry_static_file_present_resolution.total_count":
            return {"c": 100}
        if kwargs.get("query_name") == "artifact_registry_static_file_present_resolution.static_dangling_count":
            return {"c": 5}
        return {"c": 0}

    proposal = subject.build_static_file_present_resolution_proposal(fake_run_sql, repo_root=tmp_path)
    with pytest.raises(ValueError, match="no exact-hash"):
        subject.validate_static_file_present_resolution_proposal(proposal)


def test_write_static_file_present_resolution_receipts(tmp_path: Path) -> None:
    proposal = subject.StaticFilePresentResolutionProposal(
        total_rows_before=100,
        static_dangling_before=5,
        targeted_row_count=1,
        targeted_distinct_static_run_ids=1,
        targeted_distinct_packages=1,
        targeted_artifact_ids=(10,),
        targeted_static_run_ids=(100,),
        staged_action=subject.TARGET_STAGED_ACTION,
        canonical_coverage_class=subject.TARGET_COVERAGE_CLASS,
        artifact_type_counts={"static_report": 1},
        path_family_counts={"static_reports_latest": 1},
        package_counts={"com.example.alpha": 1},
        oldest_created_at_utc="2026-07-09 10:00:00",
        newest_created_at_utc="2026-07-09 10:00:00",
        all_host_files_present=True,
        all_same_hash_covered=True,
        all_have_canonical_match=True,
        all_registry_resolution_candidates=True,
        expected_count_match=True,
        sample_rows=({"artifact_id": 10},),
        target_rows=({"artifact_id": 10},),
        exact_sql_predicate="test predicate",
        apply_delete_sql="DELETE FROM artifact_registry WHERE artifact_id IN (<targeted artifact_id set>)",
    )
    paths = subject.write_static_file_present_resolution_receipts(
        tmp_path,
        stem="artifact_registry_static_file_present_resolution_test",
        proposal=proposal,
        apply_requested=False,
        apply_result=None,
    )
    for value in paths.values():
        assert Path(value).is_file()
    payload = json.loads((tmp_path / "artifact_registry_static_file_present_resolution_test.json").read_text(encoding="utf-8"))
    assert payload["format"] == "scytaledroid.artifact_registry_static_file_present_resolution_receipt.v1"
    assert payload["meta"]["targeted_row_count"] == 1
    assert "DELETE FROM artifact_registry" in (tmp_path / "artifact_registry_static_file_present_resolution_test.sql").read_text(encoding="utf-8")
