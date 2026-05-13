"""Unit tests for static run governance posture counts (no live DB)."""

from __future__ import annotations

from typing import Any

from scytaledroid.Database.db_utils.static_run_governance_checks import (
    GOVERNANCE_POSTURE_CHECKS,
    StaticRunGovernanceCounts,
    fetch_static_run_governance_counts,
)


def _fake_run_sql(
    query: str,
    params: Any = None,
    *,
    fetch: str = "none",
    dictionary: bool = False,
    query_name: str | None = None,
    **kwargs: Any,
) -> dict[str, int]:
    assert dictionary is True
    assert fetch == "one"
    values = {
        "governance_posture.failed_canonical_runs": 2,
        "governance_posture.failed_missing_run_class": 0,
        "governance_posture.completed_session_invariant_violations": 5,
    }
    assert query_name in values, query_name
    return {"c": values[query_name]}


def test_fetch_static_run_governance_counts_orders_match_tuple() -> None:
    g = fetch_static_run_governance_counts(_fake_run_sql)
    assert g == StaticRunGovernanceCounts(
        failed_canonical_runs=2,
        failed_missing_run_class=0,
        completed_session_invariant_violations=5,
    )
    assert g.non_zero_check_count() == 2


def test_governance_tuple_labels_match_dataclass_fields() -> None:
    fields = {name for name, _ in GOVERNANCE_POSTURE_CHECKS}
    assert fields == {
        "failed_canonical_runs",
        "failed_missing_run_class",
        "completed_session_invariant_violations",
    }
    sample = StaticRunGovernanceCounts(0, 0, 0)
    for name, _ in GOVERNANCE_POSTURE_CHECKS:
        assert hasattr(sample, name)
