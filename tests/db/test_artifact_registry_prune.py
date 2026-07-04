"""Tests for artifact_registry age-gated prune helpers."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from scytaledroid.Database.db_utils.artifact_registry_prune import (
    effective_cutoff_days,
    run_prune_dangling_artifact_registry,
    write_prune_receipt_bundle,
)


def test_effective_cutoff_days() -> None:
    assert effective_cutoff_days(min_age_days=90, cooling_off_days=7) == 90
    assert effective_cutoff_days(min_age_days=30, cooling_off_days=60) == 60
    assert effective_cutoff_days(min_age_days=0, cooling_off_days=0) == 1


def test_write_prune_receipt_bundle_writes_files(tmp_path: Path) -> None:
    rows = [
        {
            "artifact_id": 1,
            "run_id": "9",
            "run_type": "static",
            "artifact_type": "x",
            "link_state": "dangling_static_run",
        }
    ]
    paths = write_prune_receipt_bundle(
        tmp_path,
        stem="test_prune",
        rows=rows,
        artifact_ids=[1],
        meta={
            "generated_utc": "T",
            "cutoff_days": 90,
            "run_type_filter": "all",
            "include_null_created_at": False,
            "candidate_count": 1,
        },
        formats={"json", "csv", "sql"},
    )
    assert (tmp_path / "test_prune.json").is_file()
    data = json.loads((tmp_path / "test_prune.json").read_text(encoding="utf-8"))
    assert data["format"] == "scytaledroid.artifact_registry_prune_receipt.v1"
    assert data["artifact_rows"][0]["artifact_id"] == 1
    assert data["meta"]["cutoff_days"] == 90
    assert paths["json"].endswith("test_prune.json")


def test_run_prune_apply_requires_receipt_dir() -> None:
    run_sql = MagicMock(
        side_effect=[
            {"c": 10},
            [{"artifact_id": 1}],
        ]
    )
    run_rowcount = MagicMock(return_value=1)
    with pytest.raises(ValueError, match="receipt_dir"):
        run_prune_dangling_artifact_registry(
            run_sql,
            run_rowcount,
            min_age_days=1,
            cooling_off_days=1,
            apply=True,
            receipt_dir=None,
        )


def test_run_prune_apply_writes_then_deletes(tmp_path: Path) -> None:
    """Ordered mock: total_before, select ids, export rows, total_after; rowcount for delete."""

    export_row = {
        "artifact_id": 1,
        "run_id": "9",
        "run_type": "static",
        "artifact_type": "dep_snapshot",
        "origin": "host",
        "device_path": None,
        "host_path": None,
        "pull_status": None,
        "sha256": None,
        "size_bytes": None,
        "created_at_utc": None,
        "pulled_at_utc": None,
        "status_reason": None,
        "meta_json": None,
        "link_state": "dangling_static_run",
    }

    sql_returns: list[object] = [
        {"c": 10},
        [{"artifact_id": 1}],
        [export_row],
        {"c": 9},
    ]
    rowcount_returns = [1]

    def fake_run_sql(*_a, **_k):
        return sql_returns.pop(0)

    def fake_rowcount(*_a, **_k):
        return int(rowcount_returns.pop(0))

    out = run_prune_dangling_artifact_registry(
        fake_run_sql,
        fake_rowcount,
        min_age_days=1,
        cooling_off_days=1,
        receipt_dir=tmp_path,
        apply=True,
    )
    assert out.candidate_count == 1
    assert out.deleted_count == 1
    assert out.total_rows_after == 9
    assert out.receipt_paths
    assert list(tmp_path.glob("artifact_registry_prune_*.json"))
    receipt = json.loads(
        next(tmp_path.glob("artifact_registry_prune_*.json")).read_text(encoding="utf-8")
    )
    assert receipt["format"] == "scytaledroid.artifact_registry_prune_receipt.v1"
    assert len(receipt["artifact_rows"]) == 1


def test_run_prune_sample_ids_without_receipt() -> None:
    sql_returns: list[object] = [
        {"c": 3},
        [{"artifact_id": 100}, {"artifact_id": 101}],
    ]

    def fake_run_sql(*_a, **_k):
        return sql_returns.pop(0)

    out = run_prune_dangling_artifact_registry(
        fake_run_sql,
        MagicMock(),
        min_age_days=1,
        cooling_off_days=1,
        sample_id_limit=1,
        apply=False,
    )
    assert out.candidate_count == 2
    assert out.sample_artifact_ids == (100,)
