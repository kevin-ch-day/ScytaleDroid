from __future__ import annotations

from scytaledroid.DynamicAnalysis.menus import queue_selection as menu_selection


def _row(name: str, **kwargs) -> menu_selection.PreparedPackageSelectionRow:
    return menu_selection.PreparedPackageSelectionRow(
        full_row=[],
        op_row=[],
        build_row=None,
        dataset_app_count=0,
        dataset_complete_count=0,
        dataset_valid_runs_count=0,
        display_name=name,
        **kwargs,
    )


def test_compact_warning_line_mentions_static_refresh_need() -> None:
    warning = menu_selection._compact_warning_line(
        [
            _row(
                "Facebook",
                live_build_drift=True,
                prep_label="stale",
                qa_label="valid (L)",
                next_label="refresh static",
            )
        ]
    )
    assert warning == ""


def test_compact_warning_line_shows_hidden_refresh_count() -> None:
    warning = menu_selection._compact_warning_line(
        [
            _row("LinkedIn", live_build_drift=True),
            _row("Reddit", live_build_drift=True),
            _row("Signal", live_build_drift=True),
            _row("Snapchat", live_build_drift=True),
        ]
    )
    assert warning == ""


def test_compact_warning_line_uses_count_summaries_for_large_groups() -> None:
    rows = [
        _row("Facebook", prep_label="mixed", qa_label="valid (id_mismatch)"),
        _row("X (Twitter)", prep_label="mixed", qa_label="valid (id_mismatch)"),
        _row("Signal", lineage_state="historical_db_only"),
        _row("Snapchat", lineage_state="historical_db_only"),
        _row("Telegram", lineage_state="historical_local_only"),
    ]
    warning = menu_selection._compact_warning_line(rows)
    note = menu_selection._compact_note_line(rows)

    assert warning == ""
    assert (
        note
        == "Facebook, X (Twitter) mixed current/legacy evidence | 3 history-only apps. Press D."
    )


def test_compact_note_line_mentions_mixed_current_legacy_context() -> None:
    note = menu_selection._compact_note_line(
        [
            _row(
                "CNN",
                prep_label="mixed",
                lineage_state="current_build_observed",
                qa_label="valid (L)",
                next_label="baseline",
            )
        ]
    )
    assert note == "CNN mixed current/legacy evidence. Press D."


def test_compact_warning_line_mentions_historical_db_only() -> None:
    warning = menu_selection._compact_warning_line(
        [
            _row(
                "Facebook Messenger",
                lineage_state="historical_db_only",
                prep_label="hist-db",
                qa_label="—",
                next_label="baseline",
            )
        ]
    )
    assert warning == ""


def test_compact_note_line_mentions_historical_db_only() -> None:
    note = menu_selection._compact_note_line(
        [
            _row(
                "Facebook Messenger",
                lineage_state="historical_db_only",
                prep_label="hist-db",
                qa_label="—",
                next_label="baseline",
            )
        ]
    )
    assert note == "Facebook Messenger history-only app. Press D."


def test_compact_warning_line_keeps_current_scope_identity_mismatch() -> None:
    warning = menu_selection._compact_warning_line(
        [
            _row(
                "CNN",
                lineage_state="current_build_observed",
                qa_label="valid (id_mismatch)",
            )
        ]
    )
    assert warning == "CNN identity mismatch. Press D."


def test_compact_note_line_keeps_legacy_identity_mismatch() -> None:
    note = menu_selection._compact_note_line(
        [
            _row(
                "TikTok",
                lineage_state="historical_local_only",
                qa_label="valid (id_mismatch) (L)",
            )
        ]
    )
    assert note == "TikTok legacy identity note | TikTok history-only app. Press D."


def test_archive_blocker_summary_keeps_refresh_visible_with_overlapping_counts() -> None:
    rows = [
        _row("CNN", qa_label="invalid"),
        _row("LinkedIn", live_build_drift=True, need_baseline=3),
        _row("TikTok", need_interactive=2),
    ]

    blocker_text = menu_selection._archive_blocker_summary(rows)

    assert blocker_text == "1 review | 1 refresh | 1 baseline gap | 1 manual"
