from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from scytaledroid.DynamicAnalysis.controllers import guided_run, selected_app_review
from scytaledroid.DynamicAnalysis.services.paper_freeze_readiness import (
    PaperFreezeBuildCandidate,
    PaperFreezeRecommendation,
)
from scytaledroid.Utils.DisplayUtils import menu_utils
from tests.dynamic._guided_run_state_support import (
    make_dataset_state,
    make_recent_summary,
    one_shot_package_selector,
    patch_guided_run_context,
)

pytestmark = [pytest.mark.contract, pytest.mark.state_contract]


def test_guided_run_recent_runs_show_dataset_impact_labels(monkeypatch, capsys) -> None:
    package = "com.cnn.mobile.android.phone"
    select_package_calls, select_package = one_shot_package_selector(package)
    choice_iter = iter(["H", "0"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="CNN",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=7,
            valid_runs=7,
            baseline_valid_runs=3,
            interactive_valid_runs=2,
            quota_met=True,
            extra_valid_runs=2,
            recent_runs=(
                make_recent_summary(
                    ended_at="2026-06-29T10:00:00Z",
                    run_profile="interaction_manual",
                    interaction_level="manual",
                    valid=True,
                    countable=False,
                    cohort_eligibility="EXTRA",
                    supplemental_reason="MANUAL_EXTRA_RUN",
                    run_id="cnn-extra-1",
                    status_label="VALID",
                ),
                make_recent_summary(
                    ended_at="2026-06-29T09:00:00Z",
                    run_profile="baseline_idle",
                    interaction_level="minimal",
                    valid=True,
                    countable=False,
                    cohort_eligibility="EXTRA",
                    low_signal=True,
                    supplemental_reason="LOW_SIGNAL_IDLE",
                    run_id="cnn-low-1",
                    status_label="VALID (LOW_SIGNAL_IDLE)",
                ),
                make_recent_summary(
                    ended_at="2026-06-29T08:00:00Z",
                    run_profile="interaction_scripted",
                    interaction_level="scripted",
                    valid=True,
                    countable=False,
                    cohort_eligibility="EXTRA",
                    supplemental_reason="SCRIPTED_EXTRA_RUN",
                    run_id="cnn-script-extra-1",
                    status_label="VALID",
                ),
                make_recent_summary(
                    ended_at="2026-06-29T07:00:00Z",
                    run_profile="interaction_scripted",
                    interaction_level="scripted",
                    valid=True,
                    countable=True,
                    cohort_eligibility="COUNTABLE",
                    run_id="cnn-count-1",
                    status_label="VALID",
                ),
            ),
        ),
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choice_iter)
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None
    )

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Recent Tracker Runs" in out
    assert "Dataset" in out
    assert "retained extra" in out
    assert "quota-counted" in out


def test_dataset_impact_label_distinguishes_manual_and_scripted_extra_runs() -> None:
    manual_row = SimpleNamespace(
        valid=True, supplemental_reason="MANUAL_EXTRA_RUN", countable=False
    )
    scripted_row = SimpleNamespace(
        valid=True, supplemental_reason="SCRIPTED_EXTRA_RUN", countable=False
    )
    low_signal_row = SimpleNamespace(
        valid=True, supplemental_reason="LOW_SIGNAL_IDLE", countable=False
    )

    assert selected_app_review._dataset_impact_label(manual_row) == "retained extra (manual extra)"
    assert (
        selected_app_review._dataset_impact_label(scripted_row) == "retained extra (scripted extra)"
    )
    assert (
        selected_app_review._dataset_impact_label(low_signal_row)
        == "ML training pool (LOW_SIGNAL_IDLE)"
    )
    baseline_not_idle_row = SimpleNamespace(
        valid=True, supplemental_reason="BASELINE_NOT_IDLE", countable=False
    )
    extra_baseline_row = SimpleNamespace(
        valid=True, supplemental_reason="EXTRA_RUN", countable=False
    )
    assert (
        selected_app_review._dataset_impact_label(baseline_not_idle_row)
        == "app-active no-touch baseline tag"
    )
    assert (
        selected_app_review._dataset_impact_label(extra_baseline_row)
        == "ML training pool (supplemental baseline)"
    )


def test_guided_run_reports_historical_and_retained_extra_context(monkeypatch, capsys) -> None:
    package = "com.facebook.katana"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="Facebook",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=4,
            valid_runs=3,
            baseline_valid_runs=3,
            interactive_valid_runs=0,
            quota_met=False,
            extra_valid_runs=1,
            local_evidence_dir_count=4,
            reset_available=True,
            paper_eligible_local=4,
            quota_counted_local=3,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=4,
            historical_valid_runs=2,
            historical_build_count=1,
            interactive_extra_valid=1,
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert (
        "Retained prior-build evidence: 2 valid run(s) across 1 prior build(s) retained for analysis; not counted toward current-build quota."
        in out
    )
    assert "Qualification" in out
    assert "Strict idle  3/3" in out
    assert "Quiescent FG  0" in out
    assert "Interactive  0/4 (+1 extra)" in out


def test_guided_run_reports_low_signal_retained_extra_current_build_context(
    monkeypatch, capsys
) -> None:
    package = "com.twitter.android"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="X (Twitter)",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=4,
            valid_runs=4,
            baseline_valid_runs=2,
            interactive_valid_runs=0,
            quota_met=False,
            extra_valid_runs=2,
            local_evidence_dir_count=4,
            reset_available=True,
            paper_eligible_local=4,
            quota_counted_local=2,
            suggested_profile_from_tracker="baseline_idle",
            effective_suggested_profile="baseline_idle",
            suggested_slot=1,
            baseline_idle_low_signal_streak=2,
            baseline_low_signal_valid=2,
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Retained extra baseline: 2 low-signal idle run(s) retained outside quota." not in out
    assert "Qualification" in out
    assert "Strict idle  2/3 (+2 low)" in out
    assert "Quiescent FG  0" in out


def test_guided_run_surfaces_quiescent_fg_and_raw_interactive_when_strict_idle_holds(
    monkeypatch, capsys
) -> None:
    package = "com.zhiliaoapp.musically"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="TikTok",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
                total_runs=9,
                valid_runs=9,
                baseline_valid_runs=7,
                interactive_valid_runs=2,
                quota_met=False,
            extra_valid_runs=0,
            local_evidence_dir_count=9,
            reset_available=True,
            paper_eligible_local=9,
            quota_counted_local=2,
            suggested_profile_from_tracker="baseline_idle",
            effective_suggested_profile="baseline_idle",
            suggested_slot=1,
            baseline_not_idle_valid=7,
            paper_freeze=PaperFreezeRecommendation(
                package_name=package,
                installed_target_version_code="2024507030",
                installed_target_version_name="45.7.3",
                installed_target_static_run_id="5838",
                installed_target_base_apk_sha256="t" * 64,
                selected_build=PaperFreezeBuildCandidate(
                    package_name=package,
                    version_code="2024507030",
                    version_name="45.7.3",
                    static_run_id="5838",
                        base_apk_sha256="t" * 64,
                        strict_idle_runs=7,
                        quiescent_fg_runs=7,
                        baseline_valid_runs=7,
                        interactive_valid_runs=2,
                    valid_pcap_count=9,
                    qa_valid_count=9,
                    first_capture_at="2026-07-04T10:00:00Z",
                    last_capture_at="2026-07-04T10:35:00Z",
                    relation_to_active_target="current",
                        missing_baseline_runs=0,
                        missing_interactive_runs=2,
                        status="needs interactive",
                    static_run_ids=("5838",),
                ),
                build_candidates=(),
                refresh_candidate=False,
                retained_prior_build_selected=False,
            ),
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Strict idle  7/3" in out
    assert "Quiescent FG  7" in out
    assert "Interactive  2/4" in out
    assert "held by strict idle" not in out
    assert "Strict-idle workflow gate: incomplete" not in out
    assert "still treats baseline counts without a strict-idle versus Quiescent FG split" not in out


def test_guided_run_diagnostics_show_retained_extra_breakdown(monkeypatch, capsys) -> None:
    package = "com.cnn.mobile.android.phone"
    select_package_calls, select_package = one_shot_package_selector(package)
    choice_iter = iter(["G", "0"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="CNN",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=9,
            valid_runs=9,
            baseline_valid_runs=3,
            interactive_valid_runs=4,
            quota_met=True,
            extra_valid_runs=2,
            baseline_extra_valid=1,
            interactive_extra_valid=1,
            local_evidence_dir_count=9,
            reset_available=True,
            paper_eligible_local=9,
            quota_counted_local=7,
            suggested_profile_from_tracker="interaction_manual",
            effective_suggested_profile="interaction_manual",
            suggested_slot=None,
        ),
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choice_iter)
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None
    )

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Diagnostics" in out
    assert "Quota-counted baseline" in out
    assert "3 / 3" in out
    assert "Quota-counted interactive" in out
    assert "4 / 4" in out
    assert "ML training pool (baseline)" in out
    assert "supplemental=1 | low-signal=0 | total=1" in out
    assert "Retained extra interactive" in out
    assert "extra=1 | low-signal=0" in out


def test_selected_app_diagnostics_show_non_idle_reason_codes_and_ml_pool_no(
    monkeypatch, tmp_path, capsys
) -> None:
    package = "com.twitter.android"
    run_id = "x-non-idle-1"
    run_dir = tmp_path / "evidence" / "dynamic" / run_id / "analysis"
    run_dir.mkdir(parents=True)
    (run_dir / "pcap_report.json").write_text(
        json.dumps(
            {
                "capinfos": {"parsed": {"capture_duration_s": 480.0, "data_size_bytes": 7_800_000}},
                "startup_profile": {
                    "startup_dominant": True,
                    "startup_byte_share": 0.84,
                    "post_start_median_bytes_per_min": 41_000.0,
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {"bytes_per_second_avg": 28_500.0, "bytes_per_second_p95": 305_000.0},
                "proxies": {"quic_ratio": 0.68},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(selected_app_review.app_config, "OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(
        selected_app_review,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                package: {
                    "runs": [
                        {
                            "run_id": run_id,
                            "ended_at": "2026-07-03T00:00:00Z",
                            "run_profile": "baseline_idle",
                            "valid_dataset_run": True,
                            "countable": False,
                            "baseline_not_idle": True,
                            "baseline_not_idle_reasons": [
                                "BASELINE_BYTES_HIGH",
                                "BASELINE_QUIC_MEDIA_HEAVY",
                            ],
                            "version_code": "312031000",
                            "base_apk_sha256": "sha-active",
                        }
                    ]
                }
            }
        },
    )
    state = make_dataset_state(
        package,
        baseline_valid_runs=2,
        interactive_valid_runs=0,
        active_version_code="312031000",
        active_base_sha="sha-active",
    )

    selected_app_review.render_selected_app_diagnostics(
        package_name=package,
        display_label="X (Twitter)",
        state=state,
        queue_action="baseline",
        db_active_sessions=2,
        db_historical_sessions=5,
        menu_utils=menu_utils,
    )

    out = capsys.readouterr().out
    assert "Quiescent FG Baselines" in out
    assert "ML" in out
    assert "Quota" in out
    assert "no" in out
    rows = selected_app_review._non_idle_baseline_detail_rows(package, state)
    assert rows == [
        [
            run_id,
            "8m 0s",
            "7MB",
            "28,500 B/s",
            "305,000 B/s",
            "0.68",
            "startup-burst then quiet-tail",
            "84.0%",
            "41,000 B/min",
            "bytes high, QUIC-heavy",
            "no",
            "no",
        ]
    ]


def test_selected_app_recent_runs_show_non_idle_reason_codes_and_ml_pool_no(
    monkeypatch, tmp_path, capsys
) -> None:
    package = "com.twitter.android"
    run_id = "x-non-idle-1"
    run_dir = tmp_path / "evidence" / "dynamic" / run_id / "analysis"
    run_dir.mkdir(parents=True)
    (run_dir / "pcap_report.json").write_text(
        json.dumps(
            {
                "capinfos": {"parsed": {"capture_duration_s": 480.0, "data_size_bytes": 7_800_000}},
                "startup_profile": {
                    "startup_dominant": True,
                    "startup_byte_share": 0.84,
                    "post_start_median_bytes_per_min": 41_000.0,
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {"bytes_per_second_avg": 28_500.0, "bytes_per_second_p95": 305_000.0},
                "proxies": {"quic_ratio": 0.68},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(selected_app_review.app_config, "OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(
        selected_app_review,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                package: {
                    "runs": [
                        {
                            "run_id": run_id,
                            "ended_at": "2026-07-03T00:00:00Z",
                            "run_profile": "baseline_idle",
                            "valid_dataset_run": True,
                            "countable": False,
                            "baseline_not_idle": True,
                            "baseline_not_idle_reasons": [
                                "BASELINE_BYTES_HIGH",
                                "BASELINE_QUIC_MEDIA_HEAVY",
                            ],
                            "version_code": "312031000",
                            "base_apk_sha256": "sha-active",
                        }
                    ]
                }
            }
        },
    )
    state = make_dataset_state(
        package,
        active_version_code="312031000",
        active_base_sha="sha-active",
        recent_runs=(
            make_recent_summary(
                ended_at="2026-07-03T00:00:00Z",
                run_profile="baseline_idle",
                interaction_level="minimal",
                valid=True,
                countable=False,
                supplemental_reason="BASELINE_NOT_IDLE",
                run_id=run_id,
                status_label="VALID (BASELINE_NOT_IDLE)",
            ),
        ),
    )

    selected_app_review.render_selected_app_recent_runs(
        state,
        menu_utils=menu_utils,
        status_messages=guided_run.status_messages,
        run_profile_label_fn=lambda profile: str(profile or "—"),
    )

    out = capsys.readouterr().out
    assert "Recent Tracker Runs" in out
    assert "Quiescent FG Baselines" in out
    rows = selected_app_review._non_idle_baseline_detail_rows(package, state)
    assert rows == [
        [
            run_id,
            "8m 0s",
            "7MB",
            "28,500 B/s",
            "305,000 B/s",
            "0.68",
            "startup-burst then quiet-tail",
            "84.0%",
            "41,000 B/min",
            "bytes high, QUIC-heavy",
            "no",
            "no",
        ]
    ]


def test_guided_run_reports_historical_db_only_context(monkeypatch, capsys) -> None:
    package = "com.facebook.orca"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="Facebook Messenger",
        lineage_context={
            "db_active_sessions": 0,
            "db_historical_sessions": 11,
            "db_total_sessions": 11,
        },
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(package),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Why:" in out
    assert (
        "Retained prior-build DB evidence exists, but no current-build evidence pack is present in this workspace."
        in out
    )
    assert "1) Baseline run" in out
    assert "(default)" in out
    assert "Collect baseline evidence for the installed build." in out


def test_guided_run_current_build_db_only_offers_restore_or_recollect(monkeypatch, capsys) -> None:
    package = "com.linkedin.android"
    select_package_calls, select_package = one_shot_package_selector(package)
    prompts: list[str] = []
    choices = iter(["R", "0"])

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="LinkedIn",
        lineage_context={
            "db_active_sessions": 4,
            "db_historical_sessions": 0,
            "db_total_sessions": 4,
        },
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(package),
    )
    monkeypatch.setattr(
        guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: next(choices)
    )

    def _prompt_yes_no(message, default=False):
        del default
        prompts.append(str(message))
        return False

    monkeypatch.setattr(guided_run.prompt_utils, "prompt_yes_no", _prompt_yes_no)

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "Current build" in out
    assert "db-only" in out
    assert "R) Restore / recollect" in out
    assert "(default)" in out
    assert "local evidence pack is missing" in out
    assert "Restore / Recollect" in out
    assert (
        "Restore the missing evidence pack if you have it, or recollect a current-build baseline now."
        in out
    )
    assert any(
        "Start baseline recollection for the installed build now?" in prompt for prompt in prompts
    )


def test_guided_run_current_build_retained_local_evidence_is_not_db_only(
    monkeypatch, capsys
) -> None:
    package = "com.snapchat.android"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="Snapchat",
        lineage_context={
            "db_active_sessions": 1,
            "db_historical_sessions": 0,
            "db_total_sessions": 1,
        },
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(
            package,
            total_runs=1,
            valid_runs=0,
            baseline_valid_runs=0,
            interactive_valid_runs=0,
            extra_valid_runs=1,
            baseline_not_idle_valid=1,
            local_evidence_dir_count=1,
        ),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "current-build evidence (local+db)" in out
    assert "local evidence pack is missing" not in out
    assert "R) Restore / recollect" not in out


def test_guided_run_reports_no_evidence_anywhere_context(monkeypatch, capsys) -> None:
    package = "com.guardian"
    select_package_calls, select_package = one_shot_package_selector(package)

    patch_guided_run_context(
        monkeypatch,
        package_name=package,
        display_name="The Guardian",
    )
    monkeypatch.setattr(
        guided_run,
        "load_dataset_run_state",
        lambda _package_name, config=None: make_dataset_state(package),
    )
    monkeypatch.setattr(guided_run.prompt_utils, "get_choice", lambda *args, **kwargs: "0")

    guided_run.run_guided_dataset_run(
        select_package_from_groups=select_package,
        select_observers=lambda device_serial, mode: ["pcapdroid_capture"],
        print_device_badge=lambda *_args: None,
    )

    out = capsys.readouterr().out
    assert select_package_calls["count"] == 2
    assert "no current-build evidence" in out
    assert "No dynamic evidence exists yet for com.guardian." in out
    assert "1) Baseline run" in out
    assert "(default)" in out


def test_selected_app_latest_recent_summary_does_not_replace_scoped_current_run_with_newer_unscoped_run(
    monkeypatch,
) -> None:
    fallback = make_recent_summary(
        ended_at="2026-06-26T20:18:37.984723+00:00",
        run_profile="baseline_idle",
        interaction_level="minimal",
        valid=True,
        run_id="current-build-run",
        status_label="VALID",
    )
    newer_unscoped = make_recent_summary(
        ended_at="2026-06-27T01:00:00.000000+00:00",
        run_profile="baseline_idle",
        interaction_level="minimal",
        valid=True,
        run_id="legacy-run",
        status_label="VALID",
    )
    monkeypatch.setattr(guided_run, "recent_tracker_runs", lambda _pkg, limit=1: [newer_unscoped])

    selected = guided_run._selected_app_latest_recent_summary(
        package_name="com.twitter.android",
        state=SimpleNamespace(recent_runs=(fallback,)),
    )

    assert selected is fallback


def test_selected_app_has_identity_mismatch_uses_tracker_scope_helpers(monkeypatch) -> None:
    latest_recent = make_recent_summary(
        ended_at="2026-06-26T20:18:37.984723+00:00",
        run_profile="baseline_idle",
        interaction_level="minimal",
        valid=True,
        run_id="twitter-run-1",
        status_label="VALID",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.load_dataset_tracker",
        lambda: {
            "apps": {
                "com.twitter.android": {
                    "runs": [
                        {
                            "run_id": "twitter-run-1",
                            "ended_at": "2026-06-26T20:18:37.984723+00:00",
                            "run_profile": "baseline_idle",
                            "valid_dataset_run": True,
                        }
                    ]
                }
            }
        },
    )
    monkeypatch.setattr(
        guided_run,
        "_build_scoped_dataset_counts_shared",
        lambda *_args, **_kwargs: {
            "active_version_code": "312011000",
            "active_base_sha": "aaaabbbb",
        },
    )
    monkeypatch.setattr(
        guided_run,
        "_resolve_tracker_run_identity_shared",
        lambda _package, _run: ("312021000", "ccccdddd"),
    )

    mismatch = guided_run._selected_app_has_identity_mismatch(
        package_name="com.twitter.android",
        latest_recent=latest_recent,
        cfg=object(),
    )

    assert mismatch is True


def test_selected_app_latest_recent_summary_prefers_scoped_state_over_newer_tracker_row(
    monkeypatch,
) -> None:
    fallback = make_recent_summary(
        ended_at="2026-06-26T20:18:37.984723+00:00",
        run_profile="interaction_manual",
        interaction_level="manual",
        valid=True,
        run_id="current-valid-run",
        status_label="VALID",
    )
    newer_invalid = make_recent_summary(
        ended_at="2026-06-27T01:00:00.000000+00:00",
        run_profile="interaction_scripted",
        interaction_level="scripted",
        valid=False,
        invalid_reason_code="PCAP_MISSING",
        pcap_failure_detail="PCAP_DEVICE_FILE_MISSING",
        run_id="current-invalid-run",
        status_label="INVALID:PCAP_MISSING",
    )
    monkeypatch.setattr(guided_run, "recent_tracker_runs", lambda _pkg, limit=1: [newer_invalid])
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.load_dataset_tracker",
        lambda: {
            "apps": {
                "com.cnn.mobile.android.phone": {
                    "runs": [
                        {
                            "run_id": "current-invalid-run",
                            "ended_at": "2026-06-27T01:00:00.000000+00:00",
                            "run_profile": "interaction_scripted",
                            "valid_dataset_run": False,
                            "invalid_reason_code": "PCAP_MISSING",
                        }
                    ]
                }
            }
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.tracker_scope.resolve_active_package_identity",
        lambda _pkg: ("312021000", "aaaabbbb"),
    )
    monkeypatch.setattr(
        guided_run,
        "_resolve_tracker_run_identity_shared",
        lambda _package, _run: ("312021000", "aaaabbbb"),
    )

    selected = guided_run._selected_app_latest_recent_summary(
        package_name="com.cnn.mobile.android.phone",
        state=SimpleNamespace(recent_runs=(fallback,)),
    )

    assert selected.run_id == "current-valid-run"
    assert selected.valid is True
