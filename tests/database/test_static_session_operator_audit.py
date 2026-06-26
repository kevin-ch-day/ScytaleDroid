from __future__ import annotations

from scytaledroid.Database.db_utils.static_session_operator_audit import (
    classify_session_header_diagnostic,
    sql_literal_for_session,
)


def test_sql_literal_for_session_escapes_single_quotes() -> None:
    assert sql_literal_for_session("2026-all") == "'2026-all'"
    assert sql_literal_for_session("o'reilly") == "'o''reilly'"
    assert sql_literal_for_session("") == "''"


def test_classify_session_header_diagnostic_marks_in_progress_unrefreshed() -> None:
    status = classify_session_header_diagnostic(
        header_total_run_count=3,
        header_session_link_rows=0,
        header_rollup_rows=0,
        actual_run_rows=5,
        actual_completed_rows=0,
        actual_started_rows=5,
        actual_link_rows=0,
        actual_rollup_rows=0,
    )
    assert status == "in_progress_shell_unrefreshed"


def test_classify_session_header_diagnostic_marks_completed_header_stale() -> None:
    status = classify_session_header_diagnostic(
        header_total_run_count=12,
        header_session_link_rows=12,
        header_rollup_rows=0,
        actual_run_rows=12,
        actual_completed_rows=12,
        actual_started_rows=0,
        actual_link_rows=12,
        actual_rollup_rows=1,
    )
    assert status == "completed_header_stale"


def test_classify_session_header_diagnostic_marks_partial_in_progress_pending_links() -> None:
    status = classify_session_header_diagnostic(
        header_total_run_count=12,
        header_session_link_rows=0,
        header_rollup_rows=0,
        actual_run_rows=12,
        actual_completed_rows=3,
        actual_started_rows=9,
        actual_link_rows=0,
        actual_rollup_rows=0,
    )
    assert status == "in_progress_partial_pending_links"


def test_classify_session_header_diagnostic_keeps_interrupted_failed_session_healthy() -> None:
    status = classify_session_header_diagnostic(
        header_total_run_count=33,
        header_session_link_rows=0,
        header_rollup_rows=0,
        actual_run_rows=33,
        actual_completed_rows=0,
        actual_started_rows=0,
        actual_link_rows=0,
        actual_rollup_rows=0,
    )
    assert status == "healthy"
