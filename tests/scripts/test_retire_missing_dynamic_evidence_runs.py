from __future__ import annotations

import pytest
from scripts.db.retire_missing_dynamic_evidence_runs import _candidate_run_ids, _quote_sql_ident


def test_candidate_run_ids_requires_db_only_classification() -> None:
    rows = [
        {
            "dynamic_run_id": "run-ok",
            "classification": "missing_evidence_db_only_retirement_candidate",
            "normalized_target_exists": "False",
            "reference_hit_count": "0",
        },
        {
            "dynamic_run_id": "run-referenced",
            "classification": "missing_evidence_restore_before_retirement",
            "normalized_target_exists": "False",
            "reference_hit_count": "1",
        },
        {
            "dynamic_run_id": "run-restored",
            "classification": "missing_evidence_db_only_retirement_candidate",
            "normalized_target_exists": "True",
            "reference_hit_count": "0",
        },
    ]

    assert _candidate_run_ids(rows) == ("run-ok",)


def test_candidate_run_ids_dedupes_and_sorts() -> None:
    rows = [
        {
            "dynamic_run_id": "run-b",
            "classification": "missing_evidence_db_only_retirement_candidate",
            "normalized_target_exists": "False",
            "reference_hit_count": "0",
        },
        {
            "dynamic_run_id": "run-a",
            "classification": "missing_evidence_db_only_retirement_candidate",
            "normalized_target_exists": "False",
            "reference_hit_count": "0",
        },
        {
            "dynamic_run_id": "run-b",
            "classification": "missing_evidence_db_only_retirement_candidate",
            "normalized_target_exists": "False",
            "reference_hit_count": "0",
        },
    ]

    assert _candidate_run_ids(rows) == ("run-a", "run-b")


def test_quote_sql_ident_allowlists_plain_names() -> None:
    assert _quote_sql_ident("dynamic_sessions") == "`dynamic_sessions`"
    with pytest.raises(ValueError, match="unsafe SQL identifier"):
        _quote_sql_ident("runs`; DROP TABLE apps; --")
