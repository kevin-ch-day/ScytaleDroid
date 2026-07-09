from __future__ import annotations

import json
from pathlib import Path

import pytest
from scytaledroid.Database.db_utils import artifact_registry_static_prune as prune


def _row(
    *,
    artifact_id: int,
    run_id: int,
    host_path: str,
    primary_reason: str = "truly_detached",
    host_path_exists: bool = False,
    legacy_runs_row_present: bool = False,
    canonical_db_reference_present: bool = False,
) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "run_type": "static",
        "run_id": str(run_id),
        "static_run_id": run_id,
        "resolved_static_run_id": run_id,
        "artifact_type": "static_report",
        "host_path_family": "static_reports_latest",
        "host_path": host_path,
        "host_path_exists": host_path_exists,
        "created_at_utc": "2026-02-08 00:00:00",
        "status_reason": None,
        "missing_static_run": True,
        "legacy_runs_row_present": legacy_runs_row_present,
        "canonical_db_reference_present": canonical_db_reference_present,
        "primary_reason": primary_reason,
    }


def test_build_static_prune_proposal_default_reason(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        prune,
        "collect_artifact_registry_static_dangling_report",
        lambda run_sql, repo_root: {  # noqa: ARG005
            "static_dangling_rows": [
                _row(artifact_id=1, run_id=101, host_path=str(tmp_path / "a")),
                _row(
                    artifact_id=2,
                    run_id=102,
                    host_path=str(tmp_path / "b"),
                    primary_reason="legacy_mirror_only_file_missing",
                ),
            ]
        },
    )
    counts = {
        "artifact_registry_static_prune.total_count": {"c": 100},
        "artifact_registry_static_prune.static_dangling_count": {"c": 2},
        "artifact_registry_static_prune.dynamic_dangling_count": {"c": 50},
    }

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=True, query_name=None):  # noqa: ANN001,ARG001
        return counts[query_name]

    proposal = prune.build_static_prune_proposal(fake_run_sql, repo_root=tmp_path)
    assert proposal.targeted_row_count == 1
    assert proposal.targeted_distinct_static_run_ids == 1
    assert proposal.included_primary_reasons == ("truly_detached",)
    assert proposal.all_missing_static_run is True
    assert proposal.all_target_files_missing is True
    assert proposal.all_missing_canonical_refs is True
    assert proposal.all_missing_legacy_runs_overlap is True


def test_build_static_prune_proposal_include_legacy_missing(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        prune,
        "collect_artifact_registry_static_dangling_report",
        lambda run_sql, repo_root: {  # noqa: ARG005
            "static_dangling_rows": [
                _row(artifact_id=1, run_id=101, host_path=str(tmp_path / "a")),
                _row(
                    artifact_id=2,
                    run_id=102,
                    host_path=str(tmp_path / "b"),
                    primary_reason="legacy_mirror_only_file_missing",
                ),
            ]
        },
    )
    counts = {
        "artifact_registry_static_prune.total_count": {"c": 100},
        "artifact_registry_static_prune.static_dangling_count": {"c": 2},
        "artifact_registry_static_prune.dynamic_dangling_count": {"c": 50},
    }

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=True, query_name=None):  # noqa: ANN001,ARG001
        return counts[query_name]

    proposal = prune.build_static_prune_proposal(
        fake_run_sql,
        repo_root=tmp_path,
        include_primary_reasons=("truly_detached", "legacy_mirror_only_file_missing"),
        expected_count=2,
    )
    assert proposal.targeted_row_count == 2
    assert proposal.expected_count_match is True
    assert proposal.included_primary_reasons == (
        "truly_detached",
        "legacy_mirror_only_file_missing",
    )


def test_validate_static_prune_proposal_rejects_legacy_overlap() -> None:
    proposal = prune.StaticPruneProposal(
        total_rows_before=10,
        static_dangling_before=2,
        dynamic_dangling_before=1,
        targeted_row_count=1,
        targeted_distinct_static_run_ids=1,
        targeted_static_run_ids=(101,),
        targeted_artifact_ids=(1,),
        included_primary_reasons=("truly_detached",),
        reason_counts={"truly_detached": 1},
        artifact_type_counts={"static_report": 1},
        path_family_counts={"static_reports_latest": 1},
        oldest_created_at_utc=None,
        newest_created_at_utc=None,
        all_missing_static_run=True,
        all_target_files_missing=True,
        all_missing_canonical_refs=True,
        all_missing_legacy_runs_overlap=False,
        canonical_db_residue_count=0,
        legacy_runs_overlap_count=1,
        host_file_present_count=0,
        sample_rows=(),
        target_rows=(),
        exact_sql_predicate="x",
        apply_delete_sql="y",
        expected_count_match=None,
    )
    with pytest.raises(ValueError, match="legacy runs rows"):
        prune.validate_static_prune_proposal(proposal)


def test_write_static_prune_receipts(tmp_path: Path) -> None:
    proposal = prune.StaticPruneProposal(
        total_rows_before=100,
        static_dangling_before=2,
        dynamic_dangling_before=10,
        targeted_row_count=2,
        targeted_distinct_static_run_ids=1,
        targeted_static_run_ids=(101,),
        targeted_artifact_ids=(1, 2),
        included_primary_reasons=("truly_detached",),
        reason_counts={"truly_detached": 2},
        artifact_type_counts={"static_report": 2},
        path_family_counts={"static_reports_latest": 2},
        oldest_created_at_utc="2026-02-08 00:00:00",
        newest_created_at_utc="2026-02-08 00:00:00",
        all_missing_static_run=True,
        all_target_files_missing=True,
        all_missing_canonical_refs=True,
        all_missing_legacy_runs_overlap=True,
        canonical_db_residue_count=0,
        legacy_runs_overlap_count=0,
        host_file_present_count=0,
        sample_rows=({"artifact_id": 1},),
        target_rows=({"artifact_id": 1, "resolved_static_run_id": 101},),
        exact_sql_predicate="x",
        apply_delete_sql="y",
        expected_count_match=True,
    )
    prune.write_static_prune_receipts(
        tmp_path,
        stem="artifact_registry_static_prune_test",
        proposal=proposal,
        apply_requested=False,
    )
    assert (tmp_path / "artifact_registry_static_prune_test.json").is_file()
    assert (tmp_path / "artifact_registry_static_prune_test.csv").is_file()
    assert (tmp_path / "artifact_registry_static_prune_test.sql").is_file()
    assert (tmp_path / "artifact_registry_static_prune_run_ids_test.txt").is_file()
    payload = json.loads(
        (tmp_path / "artifact_registry_static_prune_test.json").read_text(encoding="utf-8")
    )
    assert payload["format"] == "scytaledroid.artifact_registry_static_prune_receipt.v1"
    assert payload["meta"]["targeted_row_count"] == 2
