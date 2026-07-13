from __future__ import annotations

from scytaledroid.DynamicAnalysis import tracker_scope
from scytaledroid.DynamicAnalysis.menus import queue_selection as menu_selection
from scytaledroid.DynamicAnalysis.menus.queue_prepared_view import (
    prepare_package_selection_view,
)


def test_display_action_label_matches_invalid_review_status() -> None:
    row = menu_selection.PreparedPackageSelectionRow(
        full_row=["3"],
        op_row=[],
        build_row=None,
        dataset_app_count=0,
        dataset_complete_count=0,
        dataset_valid_runs_count=0,
        display_name="ESPN",
        baseline_countable=0,
        baseline_extra=0,
        interactive_countable=0,
        interactive_extra=0,
        need_baseline=3,
        need_interactive=2,
        prep_label="ready",
        qa_label="invalid",
        next_label="baseline",
    )
    assert menu_selection._display_action_label(row) == "review"
    assert menu_selection._display_next_line_action_label(row) == "review QA"


def test_display_action_label_uses_review_for_invalid_complete_row() -> None:
    row = menu_selection.PreparedPackageSelectionRow(
        full_row=["1"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=1,
        dataset_valid_runs_count=5,
        package_name="com.cnn.mobile.android.phone",
        display_name="CNN",
        baseline_countable=3,
        interactive_countable=2,
        need_baseline=0,
        need_interactive=0,
        prep_label="current",
        qa_label="invalid",
        next_label="review QA",
        lineage_state="current_build_observed",
    )

    assert menu_selection._display_action_label(row) == "review"
    assert menu_selection._display_next_line_action_label(row) == "review QA"


def test_display_action_label_continues_interactive_after_failed_latest_attempt() -> None:
    row = menu_selection.PreparedPackageSelectionRow(
        full_row=["11"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=4,
        package_name="org.telegram.messenger",
        display_name="Telegram",
        baseline_countable=3,
        interactive_countable=1,
        need_baseline=0,
        need_interactive=3,
        prep_label="current",
        qa_label="invalid",
        next_label="manual interaction",
        technical_valid_active=4,
        lineage_state="current_build_observed",
    )

    assert menu_selection._display_action_label(row) == "interactive"
    assert menu_selection._display_next_line_action_label(row) == "interactive"


def test_prepare_view_counts_invalid_continuation_as_in_progress(monkeypatch) -> None:
    from scytaledroid.DynamicAnalysis.pcap import dataset_tracker

    monkeypatch.setattr(dataset_tracker, "load_dataset_tracker", lambda: {"apps": {}})

    row = menu_selection.PreparedPackageSelectionRow(
        full_row=["11"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=4,
        package_name="org.telegram.messenger",
        display_name="Telegram",
        baseline_countable=3,
        interactive_countable=1,
        need_baseline=0,
        need_interactive=3,
        prep_label="current",
        qa_label="invalid",
        next_label="manual interaction",
        technical_valid_active=4,
        lineage_state="current_build_observed",
    )

    prepared = prepare_package_selection_view(
        object(),
        load_dataset_packages=lambda: ["org.telegram.messenger"],
        list_packages_fn=lambda _groups: [("org.telegram.messenger", None, None, "Telegram")],
        summarize_evidence_quota_fn=lambda *_args, **_kwargs: {
            "evidence_root_exists": True,
            "quota_runs_counted": 4,
            "apps_satisfied": 0,
            "extra_eligible_runs": 0,
        },
        build_package_selection_row_fn=lambda **_kwargs: row,
        resolve_live_build_drift_map_fn=lambda *_args, **_kwargs: {},
        resolve_db_dynamic_lineage_context_map_fn=lambda *_args, **_kwargs: {},
        device_serial="ZY22JK89DR",
    )

    assert prepared is not None
    assert prepared.current_build_review_count == 0
    assert prepared.current_build_in_progress_count == 1


def test_prepare_view_loads_dataset_tracker_once_for_multiple_rows(monkeypatch) -> None:
    from scytaledroid.DynamicAnalysis.pcap import dataset_tracker

    calls = {"tracker": 0}

    def fake_load_dataset_tracker():
        calls["tracker"] += 1
        return {
            "apps": {
                "com.instagram.android": {
                    "runs": [
                        {
                            "run_id": "ig-run",
                            "ended_at": "2026-07-02T12:00:00+00:00",
                            "valid_dataset_run": True,
                        }
                    ]
                },
                "com.reddit.frontpage": {
                    "runs": [
                        {
                            "run_id": "reddit-run",
                            "ended_at": "2026-07-02T13:00:00+00:00",
                            "valid_dataset_run": True,
                        }
                    ]
                },
            }
        }

    def build_row(**kwargs):
        recent = kwargs["recent_tracker_runs"](kwargs["package"], limit=1)
        assert len(recent) == 1
        return menu_selection.PreparedPackageSelectionRow(
            full_row=["1"],
            op_row=[],
            build_row=None,
            dataset_app_count=1,
            dataset_complete_count=0,
            dataset_valid_runs_count=1,
            package_name=kwargs["package"],
            display_name=kwargs["app_label"] or kwargs["package"],
            lineage_state="current_build_observed",
        )

    monkeypatch.setattr(dataset_tracker, "load_dataset_tracker", fake_load_dataset_tracker)

    prepared = prepare_package_selection_view(
        object(),
        load_dataset_packages=lambda: ["com.instagram.android", "com.reddit.frontpage"],
        list_packages_fn=lambda _groups: [
            ("com.instagram.android", None, None, "Instagram"),
            ("com.reddit.frontpage", None, None, "Reddit"),
        ],
        summarize_evidence_quota_fn=lambda *_args, **_kwargs: {},
        build_package_selection_row_fn=build_row,
        resolve_live_build_drift_map_fn=lambda *_args, **_kwargs: {},
        resolve_db_dynamic_lineage_context_map_fn=lambda *_args, **_kwargs: {},
        device_serial="ZY22JK89DR",
    )

    assert prepared is not None
    assert len(prepared.row_models or []) == 2
    assert calls["tracker"] == 1


def test_next_recommended_row_prioritizes_review_over_manual_and_refresh() -> None:
    manual_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["1"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=3,
        package_name="com.zhiliaoapp.musically",
        display_name="TikTok",
        baseline_countable=3,
        interactive_countable=0,
        need_baseline=0,
        need_interactive=2,
        prep_label="current",
        qa_label="valid",
        next_label="manual interaction",
        lineage_state="current_build_observed",
    )
    refresh_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["2"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=3,
        package_name="com.facebook.katana",
        display_name="Facebook",
        baseline_countable=3,
        interactive_countable=0,
        need_baseline=0,
        need_interactive=2,
        prep_label="stale",
        qa_label="valid (L)",
        next_label="refresh static",
        lineage_state="current_build_stale",
        live_build_drift=True,
    )
    review_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["3"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=1,
        dataset_valid_runs_count=5,
        package_name="com.cnn.mobile.android.phone",
        display_name="CNN",
        baseline_countable=3,
        interactive_countable=2,
        need_baseline=0,
        need_interactive=0,
        prep_label="current",
        qa_label="invalid",
        next_label="review QA",
        lineage_state="current_build_observed",
    )

    picked = menu_selection._next_recommended_row([manual_row, refresh_row, review_row])
    assert picked is review_row


def test_next_recommended_row_prioritizes_non_drift_capture_over_refresh() -> None:
    manual_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["1"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=3,
        package_name="com.cnn.mobile.android.phone",
        display_name="CNN",
        baseline_countable=3,
        interactive_countable=3,
        need_baseline=0,
        need_interactive=1,
        prep_label="current",
        qa_label="valid",
        next_label="manual interaction",
        lineage_state="current_build_observed",
    )
    refresh_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["2"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=3,
        package_name="com.instagram.android",
        display_name="Instagram",
        baseline_countable=3,
        interactive_countable=0,
        need_baseline=0,
        need_interactive=4,
        prep_label="stale",
        qa_label="valid (L)",
        next_label="refresh static",
        lineage_state="current_build_stale",
        live_build_drift=True,
    )

    picked = menu_selection._next_recommended_row([refresh_row, manual_row])
    assert picked is manual_row


def test_next_recommended_row_prioritizes_empty_baseline_over_historical_baseline() -> None:
    historical_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["1"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=0,
        package_name="com.facebook.orca",
        display_name="Facebook Messenger",
        baseline_countable=0,
        interactive_countable=0,
        need_baseline=3,
        need_interactive=2,
        prep_label="hist-db",
        qa_label="—",
        next_label="baseline",
        lineage_state="historical_db_only",
    )
    empty_row = menu_selection.PreparedPackageSelectionRow(
        full_row=["2"],
        op_row=[],
        build_row=None,
        dataset_app_count=1,
        dataset_complete_count=0,
        dataset_valid_runs_count=0,
        package_name="com.guardian",
        display_name="The Guardian",
        baseline_countable=0,
        interactive_countable=0,
        need_baseline=3,
        need_interactive=2,
        prep_label="ready",
        qa_label="—",
        next_label="baseline",
        lineage_state="no_evidence_anywhere",
    )

    picked = menu_selection._next_recommended_row([historical_row, empty_row])
    assert picked is empty_row


def test_build_scoped_dataset_counts_prefers_active_plan_identity_over_latest_tracker_run() -> None:
    class _Cfg2:
        baseline_required = 3
        interactive_required = 2

    runs = [
        {
            "run_id": "legacy-facebook",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "baseline_idle",
            "version_code": "471216151",
            "base_apk_sha256": "oldsha",
            "ended_at": "2026-05-14T20:54:11+00:00",
        }
    ]

    scoped = tracker_scope.build_scoped_dataset_counts(
        "com.facebook.katana",
        runs,
        cfg=_Cfg2(),
        resolve_tracker_run_identity_fn=lambda _pkg, row: (
            str(row.get("version_code") or "") or None,
            str(row.get("base_apk_sha256") or "") or None,
        ),
        active_identity_fn=lambda _pkg: ("472143276", "newsha"),
    )

    assert scoped["baseline_countable"] == 0
    assert scoped["interactive_countable"] == 0
    assert scoped["legacy_valid"] == 1
    assert scoped["active_version_code"] == "472143276"
    assert scoped["active_base_sha"] == "newsha"


def test_build_scoped_dataset_counts_respects_explicit_non_countable_active_run() -> None:
    class _Cfg2:
        baseline_required = 3
        interactive_required = 2

    runs = [
        {
            "run_id": "cnn-1",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "baseline_idle",
            "version_code": "19250507",
            "base_apk_sha256": "sha-new",
            "ended_at": "2026-06-28T14:58:21+00:00",
            "countable": True,
        },
        {
            "run_id": "cnn-2",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "baseline_idle",
            "version_code": "19250507",
            "base_apk_sha256": "sha-new",
            "ended_at": "2026-06-28T15:03:39+00:00",
            "countable": True,
        },
        {
            "run_id": "cnn-3",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "baseline_idle",
            "version_code": "19250507",
            "base_apk_sha256": "sha-new",
            "ended_at": "2026-06-28T15:09:47+00:00",
            "countable": False,
            "low_signal": True,
            "extra_run": 1,
        },
    ]

    scoped = tracker_scope.build_scoped_dataset_counts(
        "com.cnn.mobile.android.phone",
        runs,
        cfg=_Cfg2(),
        resolve_tracker_run_identity_fn=lambda _pkg, row: (
            str(row.get("version_code") or "") or None,
            str(row.get("base_apk_sha256") or "") or None,
        ),
        active_identity_fn=lambda _pkg: ("19250507", "sha-new"),
    )

    assert scoped["baseline_countable"] == 2
    assert scoped["baseline_extra"] == 0
    assert scoped["baseline_low_signal_supplemental"] == 1
    assert scoped["interactive_countable"] == 0
    assert scoped["technical_valid_active"] == 3


def test_build_scoped_dataset_counts_repairs_app_active_no_touch_baseline() -> None:
    class _Cfg2:
        baseline_required = 3
        interactive_required = 2

    runs = [
        {
            "run_id": "pin-active",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "baseline_idle",
            "version_code": "14268010",
            "base_apk_sha256": "sha-current",
            "ended_at": "2026-07-08T19:45:00+00:00",
            "countable": False,
            "extra_run": 1,
            "low_signal": False,
            "baseline_not_idle": True,
        }
    ]

    scoped = tracker_scope.build_scoped_dataset_counts(
        "com.pinterest",
        runs,
        cfg=_Cfg2(),
        resolve_tracker_run_identity_fn=lambda _pkg, row: (
            str(row.get("version_code") or "") or None,
            str(row.get("base_apk_sha256") or "") or None,
        ),
        active_identity_fn=lambda _pkg: ("14268010", "sha-current"),
    )

    assert scoped["baseline_countable"] == 1
    assert scoped["baseline_not_idle_supplemental"] == 0
    assert scoped["baseline_low_signal_supplemental"] == 0
    assert scoped["technical_valid_active"] == 1


def test_build_scoped_dataset_counts_tracks_explicit_non_countable_interactive_extra() -> None:
    class _Cfg2:
        baseline_required = 3
        interactive_required = 2

    runs = [
        {
            "run_id": "cnn-b1",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "baseline_idle",
            "version_code": "19250507",
            "base_apk_sha256": "sha-new",
            "ended_at": "2026-06-28T14:58:21+00:00",
            "countable": True,
        },
        {
            "run_id": "cnn-b2",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "baseline_idle",
            "version_code": "19250507",
            "base_apk_sha256": "sha-new",
            "ended_at": "2026-06-28T15:03:39+00:00",
            "countable": True,
        },
        {
            "run_id": "cnn-b3",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "baseline_idle",
            "version_code": "19250507",
            "base_apk_sha256": "sha-new",
            "ended_at": "2026-06-28T15:09:47+00:00",
            "countable": True,
        },
        {
            "run_id": "cnn-i1",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "interaction_manual",
            "version_code": "19250507",
            "base_apk_sha256": "sha-new",
            "ended_at": "2026-06-28T15:11:47+00:00",
            "countable": True,
        },
        {
            "run_id": "cnn-i2",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "interaction_manual",
            "version_code": "19250507",
            "base_apk_sha256": "sha-new",
            "ended_at": "2026-06-28T15:13:47+00:00",
            "countable": True,
        },
        {
            "run_id": "cnn-i3-extra",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": "interaction_manual",
            "version_code": "19250507",
            "base_apk_sha256": "sha-new",
            "ended_at": "2026-06-28T15:15:47+00:00",
            "countable": False,
            "extra_run": 1,
        },
    ]

    scoped = tracker_scope.build_scoped_dataset_counts(
        "com.cnn.mobile.android.phone",
        runs,
        cfg=_Cfg2(),
        resolve_tracker_run_identity_fn=lambda _pkg, row: (
            str(row.get("version_code") or "") or None,
            str(row.get("base_apk_sha256") or "") or None,
        ),
        active_identity_fn=lambda _pkg: ("19250507", "sha-new"),
    )

    assert scoped["baseline_countable"] == 3
    assert scoped["interactive_countable"] == 2
    assert scoped["interactive_extra"] == 1
    assert scoped["interactive_manual_extra"] == 1
    assert scoped["interactive_low_signal_supplemental"] == 0
    assert scoped["technical_valid_active"] == 6
