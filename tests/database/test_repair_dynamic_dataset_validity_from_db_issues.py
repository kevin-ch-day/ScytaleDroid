from __future__ import annotations

import json
from typing import Any

from scripts.db import repair_dynamic_dataset_validity_from_db_issues as repair


class FakeCoreQueries:
    def __init__(self) -> None:
        self.sql_calls: list[tuple[str, tuple[Any, ...], str | None]] = []
        self.rowcount_calls: list[tuple[str, tuple[Any, ...], str | None]] = []

    def run_sql(
        self,
        query: str,
        params: tuple[Any, ...] = (),
        *,
        fetch: str = "none",
        query_name: str | None = None,
        **_: Any,
    ) -> list[dict[str, Any]]:
        self.sql_calls.append((query, params, query_name))
        return []

    def run_sql_rowcount(
        self,
        query: str,
        params: tuple[Any, ...] = (),
        *,
        query_name: str | None = None,
        **_: Any,
    ) -> int:
        self.rowcount_calls.append((query, params, query_name))
        return 1 if params[-1] == "updated-run" else 0


def _row(**overrides: Any) -> dict[str, Any]:
    row = {
        "dynamic_run_id": "run-1",
        "package_name": "com.pinterest",
        "version_name": "14.6.0",
        "version_code": 140600,
        "status": "success",
        "pcap_valid": 1,
        "pcap_bytes": 123456,
        "current_valid_dataset_run": None,
        "current_countable": None,
        "current_invalid_reason_code": None,
        "issue_row_id": 42,
        "issue_created_at": "2026-02-01 00:00:00",
        "details_json": json.dumps(
            {
                "valid_dataset_run": True,
                "countable": False,
                "invalid_reason_code": None,
                "sampling_duration_seconds": 301.5,
            }
        ),
    }
    row.update(overrides)
    return row


def test_classify_candidate_from_valid_issue_payload() -> None:
    classified = repair._classify_row(_row())

    assert classified["reason"] == "candidate"
    assert classified["new_valid_dataset_run"] == 1
    assert classified["new_countable"] == 0
    assert classified["new_sampling_duration_seconds"] == 301.5


def test_classify_blocks_non_success_or_invalid_pcap() -> None:
    assert repair._classify_row(_row(status="failed"))["reason"] == "status_not_success"
    assert repair._classify_row(_row(pcap_valid=0))["reason"] == "pcap_not_valid"


def test_classify_blocks_payload_that_does_not_prove_validity() -> None:
    row = _row(details_json=json.dumps({"valid_dataset_run": False, "countable": False}))

    classified = repair._classify_row(row)

    assert classified["reason"] == "issue_payload_not_valid_dataset_run"
    assert classified["new_valid_dataset_run"] == 0


def test_fetch_issue_rows_scopes_by_package_and_run_ids() -> None:
    fake = FakeCoreQueries()

    repair._fetch_issue_rows(
        fake,
        package="com.pinterest",
        run_ids=["run-a", "run-b"],
    )

    query, params, name = fake.sql_calls[0]
    assert name == "repair_dynamic_dataset_validity_from_db_issues.fetch"
    assert "ds.package_name = %s" in query
    assert "ds.dynamic_run_id IN (%s, %s)" in query
    assert params == ("com.pinterest", "run-a", "run-b")


def test_apply_candidates_updates_only_by_run_id_and_null_validity() -> None:
    fake = FakeCoreQueries()
    candidates = [
        {
            "dynamic_run_id": "updated-run",
            "new_valid_dataset_run": 1,
            "new_countable": 1,
            "new_invalid_reason_code": None,
            "new_sampling_duration_seconds": 300,
        },
        {
            "dynamic_run_id": "stale-run",
            "new_valid_dataset_run": 1,
            "new_countable": 0,
            "new_invalid_reason_code": None,
            "new_sampling_duration_seconds": 301,
        },
    ]

    updated = repair._apply_candidates(fake, candidates)

    assert updated == {"updated-run"}
    assert len(fake.rowcount_calls) == 2
    query, params, name = fake.rowcount_calls[0]
    assert name == "repair_dynamic_dataset_validity_from_db_issues.apply_one"
    assert "WHERE dynamic_run_id = %s" in query
    assert "AND valid_dataset_run IS NULL" in query
    assert params[-1] == "updated-run"
