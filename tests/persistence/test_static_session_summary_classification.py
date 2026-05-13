from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence.static_session_summary import (
    classify_static_session_status_and_disposition,
)


def _call(**kwargs):
    defaults = dict(
        session_stamp="s",
        scope_label="Research Dataset Alpha",
        total_run_count=1,
        completed_run_count=0,
        failed_run_count=0,
        interrupted_run_count=0,
        persist_error_run_count=0,
        missing_artifacts_run_count=0,
    )
    defaults.update(kwargs)
    return classify_static_session_status_and_disposition(**defaults)


def test_classification_completed_full_library_via_stamp():
    st, disp = _call(
        session_stamp="20260510-all-full",
        total_run_count=10,
        completed_run_count=10,
        failed_run_count=0,
    )
    assert st == "COMPLETED"
    assert disp == "completed_full_session"


def test_classification_completed_full_library_via_scope():
    st, disp = _call(
        session_stamp="plain",
        scope_label="All harvested apps",
        total_run_count=3,
        completed_run_count=3,
        failed_run_count=0,
    )
    assert st == "COMPLETED"
    assert disp == "completed_full_session"


def test_classification_completed_profile_session():
    st, disp = _call(
        session_stamp="20260502-rda-full",
        scope_label="Research Dataset Alpha",
        total_run_count=4,
        completed_run_count=4,
        failed_run_count=0,
    )
    assert st == "COMPLETED"
    assert disp == "completed_profile_session"


def test_classification_mixed_completed_failed_session():
    st, disp = _call(
        total_run_count=4,
        completed_run_count=2,
        failed_run_count=2,
        interrupted_run_count=0,
    )
    assert st == "PARTIAL"
    assert disp == "mixed_completed_failed_session"


def test_classification_interrupted_partial_when_all_failed_with_interrupt_signals():
    st, disp = _call(
        total_run_count=3,
        completed_run_count=0,
        failed_run_count=3,
        interrupted_run_count=2,
        persist_error_run_count=1,
    )
    assert st == "INTERRUPTED"
    assert disp == "interrupted_partial_session"


def test_classification_broken_persist_error_when_all_failed_with_persist_but_no_interrupt_count():
    st, disp = _call(
        total_run_count=2,
        completed_run_count=0,
        failed_run_count=2,
        interrupted_run_count=0,
        persist_error_run_count=2,
    )
    assert st == "FAILED"
    assert disp == "broken_persist_error_session"


def test_classification_missing_finalization_is_still_completed_full_until_links_roll_in():
    """Disposition follows run outcomes only; link/rollup tallies live on refresh COUNTs."""

    st, disp = _call(
        session_stamp="20260428-all-full",
        scope_label="",
        total_run_count=12,
        completed_run_count=12,
        failed_run_count=0,
    )
    assert st == "COMPLETED"
    assert disp == "completed_full_session"


def test_classification_unknown_when_empty_total():
    st, disp = _call(total_run_count=0)
    assert st == "UNKNOWN"
    assert disp == "unknown_needs_review"


def test_classification_in_progress_runs_roll_to_unknown_status():
    """All STARTED (no COMPLETED/FAILED rows in rollup) → coarse UNKNOWN + disposition unknown."""

    st, disp = _call(
        total_run_count=3,
        completed_run_count=0,
        failed_run_count=0,
        interrupted_run_count=0,
    )
    assert st == "UNKNOWN"
    assert disp == "unknown_needs_review"
