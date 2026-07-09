from __future__ import annotations

from datetime import UTC, datetime

from scripts.db.prune_failed_static_sessions import _select_candidates


def test_select_candidates_keeps_only_old_superseded_failed_interrupted_sessions() -> None:
    now = datetime(2026, 6, 26, 12, 0, 0, tzinfo=UTC).replace(tzinfo=None)
    rows = [
        {
            "session_stamp": "20260612-all-full",
            "scope_label": "All harvested apps",
            "session_disposition": "interrupted_partial_session",
            "cleanup_status": "none",
            "total_run_count": 124,
            "completed_run_count": 0,
            "failed_run_count": 124,
            "first_created_at": datetime(2026, 6, 12, 17, 54, 33),
            "last_ended_at": datetime(2026, 6, 13, 0, 16, 42),
            "superseding_session_stamp": "20260613-all-full",
            "superseding_disposition": "completed_full_session",
            "superseding_last_ended_at": datetime(2026, 6, 14, 4, 20, 38),
        },
        {
            "session_stamp": "20260626-all-full",
            "scope_label": "All harvested apps",
            "session_disposition": "interrupted_partial_session",
            "cleanup_status": "none",
            "total_run_count": 26,
            "completed_run_count": 0,
            "failed_run_count": 26,
            "first_created_at": datetime(2026, 6, 26, 0, 9, 34),
            "last_ended_at": datetime(2026, 6, 26, 5, 27, 14),
            "superseding_session_stamp": "20260625-all-full",
            "superseding_disposition": "completed_full_session",
            "superseding_last_ended_at": datetime(2026, 6, 25, 23, 32, 24),
        },
        {
            "session_stamp": "20260509-all-full",
            "scope_label": "All harvested apps",
            "session_disposition": "mixed_completed_failed_session",
            "cleanup_status": "review",
            "total_run_count": 144,
            "completed_run_count": 101,
            "failed_run_count": 43,
            "first_created_at": datetime(2026, 5, 9, 20, 2, 7),
            "last_ended_at": datetime(2026, 5, 10, 2, 43, 39),
            "superseding_session_stamp": "20260510-all-full-145",
            "superseding_disposition": "completed_full_session",
            "superseding_last_ended_at": datetime(2026, 5, 10, 20, 38, 54),
        },
        {
            "session_stamp": "20260511-all-full",
            "scope_label": "All harvested apps",
            "session_disposition": "interrupted_partial_session",
            "cleanup_status": "none",
            "total_run_count": 33,
            "completed_run_count": 0,
            "failed_run_count": 33,
            "first_created_at": datetime(2026, 5, 11, 10, 32, 22),
            "last_ended_at": datetime(2026, 5, 11, 15, 58, 50),
            "superseding_session_stamp": "",
            "superseding_disposition": "",
            "superseding_last_ended_at": None,
        },
    ]

    candidates = _select_candidates(rows, older_than_days=7, now=now)

    assert [item.session_stamp for item in candidates] == ["20260612-all-full"]
    assert candidates[0].superseding_session_stamp == "20260613-all-full"
    assert candidates[0].age_days >= 7


def test_select_candidates_can_be_scoped_to_explicit_sessions() -> None:
    now = datetime(2026, 6, 26, 12, 0, 0, tzinfo=UTC).replace(tzinfo=None)
    rows = [
        {
            "session_stamp": "20260612-all-full",
            "scope_label": "All harvested apps",
            "session_disposition": "interrupted_partial_session",
            "cleanup_status": "none",
            "total_run_count": 124,
            "completed_run_count": 0,
            "failed_run_count": 124,
            "first_created_at": datetime(2026, 6, 12, 17, 54, 33),
            "last_ended_at": datetime(2026, 6, 13, 0, 16, 42),
            "superseding_session_stamp": "20260613-all-full",
            "superseding_disposition": "completed_full_session",
            "superseding_last_ended_at": datetime(2026, 6, 14, 4, 20, 38),
        }
    ]

    candidates = _select_candidates(
        rows,
        older_than_days=7,
        now=now,
        only_sessions={"20260612-all-full"},
    )
    assert [item.session_stamp for item in candidates] == ["20260612-all-full"]

    filtered_out = _select_candidates(
        rows,
        older_than_days=7,
        now=now,
        only_sessions={"20260614-all-full"},
    )
    assert filtered_out == []
