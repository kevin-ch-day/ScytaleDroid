from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.Database.db_utils.artifact_registry_static_dep_snapshot_dedupe import (
    apply_static_dep_snapshot_dedupe,
    build_static_dep_snapshot_dedupe_proposal,
)


def test_build_dedupe_proposal_reports_counts() -> None:
    def fake_run_sql(_sql: str, _params=(), *, query_name=None, **_kwargs):
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.groups":
            return [
                {
                    "run_id": "100",
                    "static_run_id": 100,
                    "host_path": "/tmp/dep.json",
                    "rows_n": 2,
                    "distinct_sha256_count": 2,
                    "created_at_min_utc": "2026-06-25 00:00:00",
                    "created_at_max_utc": "2026-06-25 00:00:01",
                }
            ]
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.delete_rows":
            return [
                {
                    "artifact_id": 11,
                    "run_id": "100",
                    "static_run_id": 100,
                    "artifact_type": "dep_snapshot",
                    "host_path": "/tmp/dep.json",
                    "sha256": "old",
                    "size_bytes": 123,
                    "created_at_utc": "2026-06-25 00:00:00",
                }
            ]
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.keep_rows":
            return [
                {
                    "artifact_id": 12,
                    "run_id": "100",
                    "static_run_id": 100,
                    "host_path": "/tmp/dep.json",
                }
            ]
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.summary":
            return {
                "duplicate_group_count": 1,
                "duplicate_row_count": 1,
                "affected_run_count": 1,
            }
        raise AssertionError(query_name)

    proposal = build_static_dep_snapshot_dedupe_proposal(fake_run_sql)

    assert proposal.duplicate_group_count == 1
    assert proposal.duplicate_row_count == 1
    assert proposal.affected_run_count == 1
    assert proposal.candidate_delete_ids == (11,)
    assert proposal.keep_ids == (12,)
    assert proposal.path_family_counts == {"other": 1}


def test_apply_dedupe_requires_receipt_dir_when_candidates_exist(tmp_path: Path) -> None:
    def fake_run_sql(_sql: str, _params=(), *, query_name=None, **_kwargs):
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.groups":
            return [
                {
                    "run_id": "100",
                    "static_run_id": 100,
                    "host_path": "/tmp/dep.json",
                    "rows_n": 2,
                    "distinct_sha256_count": 2,
                    "created_at_min_utc": "a",
                    "created_at_max_utc": "b",
                }
            ]
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.delete_rows":
            return [
                {
                    "artifact_id": 11,
                    "run_id": "100",
                    "static_run_id": 100,
                    "artifact_type": "dep_snapshot",
                    "host_path": "/tmp/dep.json",
                    "sha256": "old",
                    "size_bytes": 1,
                    "created_at_utc": "a",
                }
            ]
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.keep_rows":
            return [
                {
                    "artifact_id": 12,
                    "run_id": "100",
                    "static_run_id": 100,
                    "host_path": "/tmp/dep.json",
                }
            ]
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.summary":
            return {"duplicate_group_count": 1, "duplicate_row_count": 1, "affected_run_count": 1}
        raise AssertionError(query_name)

    with pytest.raises(ValueError, match="receipt_dir is required"):
        apply_static_dep_snapshot_dedupe(
            fake_run_sql, lambda *_a, **_k: 0, receipt_dir=None, apply=False
        )


def test_apply_dedupe_deletes_candidate_rows(tmp_path: Path) -> None:
    summary_rows = iter(
        (
            {"duplicate_group_count": 1, "duplicate_row_count": 1, "affected_run_count": 1},
            {"duplicate_group_count": 0, "duplicate_row_count": 0, "affected_run_count": 0},
        )
    )

    def fake_run_sql(_sql: str, _params=(), *, query_name=None, **_kwargs):
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.groups":
            return [
                {
                    "run_id": "100",
                    "static_run_id": 100,
                    "host_path": "/tmp/dep.json",
                    "rows_n": 2,
                    "distinct_sha256_count": 2,
                    "created_at_min_utc": "a",
                    "created_at_max_utc": "b",
                }
            ]
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.delete_rows":
            return [
                {
                    "artifact_id": 11,
                    "run_id": "100",
                    "static_run_id": 100,
                    "artifact_type": "dep_snapshot",
                    "host_path": "/tmp/dep.json",
                    "sha256": "old",
                    "size_bytes": 1,
                    "created_at_utc": "a",
                }
            ]
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.keep_rows":
            return [
                {
                    "artifact_id": 12,
                    "run_id": "100",
                    "static_run_id": 100,
                    "host_path": "/tmp/dep.json",
                }
            ]
        if query_name == "artifact_registry_static_dep_snapshot_dedupe.summary":
            return next(summary_rows)
        raise AssertionError(query_name)

    deletes: list[tuple[str, tuple[object, ...], str | None]] = []

    def fake_run_sql_rowcount(sql: str, params=(), *, query_name=None, **_kwargs) -> int:
        deletes.append((sql, tuple(params), query_name))
        return 1

    proposal, result, receipt_paths = apply_static_dep_snapshot_dedupe(
        fake_run_sql,
        fake_run_sql_rowcount,
        receipt_dir=tmp_path,
        apply=True,
    )

    assert proposal.duplicate_row_count == 1
    assert result is not None
    assert result.deleted_count == 1
    assert result.duplicate_row_count_after == 0
    assert deletes
    assert "DELETE FROM artifact_registry WHERE artifact_id IN (%s)" in deletes[0][0]
    assert receipt_paths["json"].endswith(".json")
