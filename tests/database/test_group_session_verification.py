"""Unit tests for status-aware group static session verification."""

from __future__ import annotations

from datetime import datetime

from scytaledroid.Database.db_scripts.static_run_audit import compute_group_session_verification

_END = datetime(2026, 5, 9, 12, 0, 0)


def test_group_partial_101_completed_43_failed_terminal() -> None:
    """Synthetic session: all completed apps have summaries; failed apps are terminal."""
    runs: list[tuple[int, str | None, object | None, str | None, str | None]] = [
        (i, "COMPLETED", _END, "", "") for i in range(1, 102)
    ] + [(i, "FAILED", _END, "err", "") for i in range(102, 145)]
    fs = frozenset(range(1, 102))
    ss = frozenset(range(1, 102))
    gv = compute_group_session_verification(
        runs=runs, findings_summary_ids=fs, string_summary_ids=ss
    )
    assert gv.overall == "PARTIAL"
    assert gv.completed_total == 101
    assert gv.failed_total == 43
    assert gv.started_total == 0
    assert not gv.completed_missing_findings_summary
    assert not gv.completed_missing_string_summary
    assert not gv.failed_nonterminal


def test_error_completed_missing_findings_summary() -> None:
    runs = [(1, "COMPLETED", _END, "", "")]
    gv = compute_group_session_verification(
        runs=runs,
        findings_summary_ids=frozenset(),
        string_summary_ids=frozenset([1]),
    )
    assert gv.overall == "ERROR"
    assert gv.completed_missing_findings_summary == (1,)


def test_error_completed_missing_string_summary() -> None:
    runs = [(1, "COMPLETED", _END, "", "")]
    gv = compute_group_session_verification(
        runs=runs,
        findings_summary_ids=frozenset([1]),
        string_summary_ids=frozenset(),
    )
    assert gv.overall == "ERROR"
    assert gv.completed_missing_string_summary == (1,)


def test_ok_all_completed_with_summaries() -> None:
    runs = [(1, "COMPLETED", _END, "", "")]
    gv = compute_group_session_verification(
        runs=runs,
        findings_summary_ids=frozenset([1]),
        string_summary_ids=frozenset([1]),
    )
    assert gv.overall == "OK"


def test_error_failed_nonterminal() -> None:
    runs = [(1, "FAILED", None, "", "")]
    gv = compute_group_session_verification(
        runs=runs,
        findings_summary_ids=frozenset(),
        string_summary_ids=frozenset(),
    )
    assert gv.overall == "ERROR"
    assert gv.failed_nonterminal == (1,)


def test_partial_started_runs() -> None:
    runs = [
        (1, "COMPLETED", _END, "", ""),
        (2, "STARTED", None, "", ""),
    ]
    gv = compute_group_session_verification(
        runs=runs,
        findings_summary_ids=frozenset([1]),
        string_summary_ids=frozenset([1]),
    )
    assert gv.overall == "PARTIAL"
    assert gv.started_total == 1
