from __future__ import annotations

from scytaledroid.DynamicAnalysis.services import paper_freeze_readiness as subject


def _run(
    *,
    run_id: str,
    version_code: str,
    version_name: str,
    static_run_id: str,
    base_sha: str,
    profile: str,
    valid: bool = True,
    pcap: bool = True,
    paper_eligible: bool | None = None,
    baseline_not_idle: bool = False,
    ended_at: str = "2026-07-04T10:00:00Z",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "run_id": run_id,
        "version_code": version_code,
        "version_name": version_name,
        "static_run_id": static_run_id,
        "base_apk_sha256": base_sha,
        "run_profile": profile,
        "valid_dataset_run": valid,
        "pcap_available": pcap,
        "baseline_not_idle": baseline_not_idle,
        "ended_at": ended_at,
    }
    if paper_eligible is not None:
        payload["paper_eligible"] = paper_eligible
    return payload


def test_paper_freeze_excludes_explicitly_ineligible_runs_and_records_them(monkeypatch) -> None:
    monkeypatch.setattr(subject, "active_research_cohort_packages", lambda: ("com.cnn.mobile.android.phone",))
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    runs = [
        _run(
            run_id="cnn-b1",
            version_code="19250507",
            version_name="26.13.0",
            static_run_id="5389",
            base_sha="a" * 64,
            profile="baseline_idle",
        ),
        _run(
            run_id="cnn-excluded-script",
            version_code="19250507",
            version_name="26.13.0",
            static_run_id="5389",
            base_sha="a" * 64,
            profile="interaction_scripted",
            paper_eligible=False,
        ),
    ]
    runs[1]["paper_exclusion_primary_reason_code"] = "EXCLUDED_SCRIPT_ABORT"
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: ("ok", {"apps": {"com.cnn.mobile.android.phone": {"runs": runs}}}, None),
    )
    monkeypatch.setattr(subject, "resolve_active_package_identity", lambda package: ("19250507", "a" * 64))

    manifest = subject.build_paper_freeze_manifest()

    row = manifest["apps"][0]
    assert row["selected_dynamic_run_ids"] == "cnn-b1"
    assert row["interactive_count"] == 0
    assert row["paper_excluded_run_count"] == 1
    assert row["paper_excluded_dynamic_run_ids"] == "cnn-excluded-script"
    assert row["paper_exclusion_reason_codes"] == "EXCLUDED_SCRIPT_ABORT"
    assert manifest["selection_contract"] == {
        "requires_valid_dataset_run": True,
        "explicit_paper_ineligible_runs": "excluded",
        "missing_paper_eligibility_field": "retained for legacy compatibility",
    }
    assert manifest["summary"]["selected_dynamic_runs"] == 1
    assert manifest["summary"]["explicitly_paper_excluded_runs"] == 1


def test_recommend_paper_freeze_selects_prior_build_with_better_coverage() -> None:
    runs = [
        _run(
            run_id="wa-b1",
            version_code="262408020",
            version_name="2.26.24.80",
            static_run_id="5700",
            base_sha="a" * 64,
            profile="baseline_connected",
            ended_at="2026-07-01T10:00:00Z",
        ),
        _run(
            run_id="wa-b2",
            version_code="262408020",
            version_name="2.26.24.80",
            static_run_id="5700",
            base_sha="a" * 64,
            profile="baseline_connected",
            ended_at="2026-07-01T10:05:00Z",
        ),
        _run(
            run_id="wa-b3",
            version_code="262408020",
            version_name="2.26.24.80",
            static_run_id="5700",
            base_sha="a" * 64,
            profile="baseline_connected",
            ended_at="2026-07-01T10:10:00Z",
        ),
        _run(
            run_id="wa-i1",
            version_code="262408020",
            version_name="2.26.24.80",
            static_run_id="5700",
            base_sha="a" * 64,
            profile="interaction_manual",
            ended_at="2026-07-01T10:15:00Z",
        ),
        _run(
            run_id="wa-i2",
            version_code="262408020",
            version_name="2.26.24.80",
            static_run_id="5700",
            base_sha="a" * 64,
            profile="interaction_manual",
            ended_at="2026-07-01T10:20:00Z",
        ),
        _run(
            run_id="wa-i3",
            version_code="262408020",
            version_name="2.26.24.80",
            static_run_id="5700",
            base_sha="a" * 64,
            profile="interaction_scripted",
            ended_at="2026-07-01T10:25:00Z",
        ),
        _run(
            run_id="wa-i4",
            version_code="262408020",
            version_name="2.26.24.80",
            static_run_id="5700",
            base_sha="a" * 64,
            profile="interaction_manual",
            ended_at="2026-07-01T10:30:00Z",
        ),
        _run(
            run_id="wa-i5",
            version_code="262408020",
            version_name="2.26.24.80",
            static_run_id="5700",
            base_sha="a" * 64,
            profile="interaction_manual",
            ended_at="2026-07-01T10:35:00Z",
        ),
    ]

    recommendation = subject.recommend_paper_freeze_for_runs(
        "com.whatsapp",
        runs,
        active_identity=("262508000", "b" * 64),
    )

    assert recommendation.installed_target_version_code == "262508000"
    assert recommendation.selected_build is not None
    assert recommendation.selected_build.version_code == "262408020"
    assert recommendation.selected_build.static_run_id == "5700"
    assert recommendation.selected_build.static_run_ids == ("5700",)
    assert recommendation.selected_build.relation_to_active_target == "prior-build"
    assert recommendation.selected_build.strict_idle_runs == 3
    assert recommendation.selected_build.quiescent_fg_runs == 0
    assert recommendation.selected_build.baseline_valid_runs == 3
    assert recommendation.selected_build.interactive_valid_runs == 5
    assert recommendation.selected_build.status == "ready"
    assert recommendation.refresh_candidate is True
    assert recommendation.retained_prior_build_selected is True


def test_recommend_paper_freeze_never_relabels_run_as_current_without_matching_identity() -> None:
    runs = [
        _run(
            run_id="x-1",
            version_code="312021000",
            version_name="12.2.1",
            static_run_id="5001",
            base_sha="c" * 64,
            profile="baseline_idle",
        )
    ]

    recommendation = subject.recommend_paper_freeze_for_runs(
        "com.twitter.android",
        runs,
        active_identity=("312031000", "d" * 64),
    )

    assert recommendation.selected_build is not None
    assert recommendation.selected_build.version_code == "312021000"
    assert recommendation.selected_build.relation_to_active_target == "prior-build"
    assert recommendation.installed_target_version_code == "312031000"
    assert recommendation.refresh_candidate is True


def test_recommend_paper_freeze_groups_same_build_across_static_runs() -> None:
    runs = [
        _run(
            run_id="cnn-b1",
            version_code="19250507",
            version_name="26.13.0",
            static_run_id="4911",
            base_sha="e" * 64,
            profile="baseline_idle",
            ended_at="2026-07-01T10:00:00Z",
        ),
        _run(
            run_id="cnn-b2",
            version_code="19250507",
            version_name="26.13.0",
            static_run_id="5093",
            base_sha="e" * 64,
            profile="baseline_idle",
            ended_at="2026-07-01T10:05:00Z",
        ),
        _run(
            run_id="cnn-b3",
            version_code="19250507",
            version_name="26.13.0",
            static_run_id="5389",
            base_sha="e" * 64,
            profile="baseline_idle",
            ended_at="2026-07-01T10:10:00Z",
        ),
        _run(
            run_id="cnn-i1",
            version_code="19250507",
            version_name="26.13.0",
            static_run_id="4911",
            base_sha="e" * 64,
            profile="interaction_scripted",
            ended_at="2026-07-01T10:15:00Z",
        ),
        _run(
            run_id="cnn-i2",
            version_code="19250507",
            version_name="26.13.0",
            static_run_id="5563",
            base_sha="e" * 64,
            profile="interaction_manual",
            ended_at="2026-07-01T10:20:00Z",
        ),
        _run(
            run_id="cnn-i3",
            version_code="19250507",
            version_name="26.13.0",
            static_run_id="5563",
            base_sha="e" * 64,
            profile="interaction_manual",
            ended_at="2026-07-01T10:25:00Z",
        ),
        _run(
            run_id="cnn-i4",
            version_code="19250507",
            version_name="26.13.0",
            static_run_id="5093",
            base_sha="e" * 64,
            profile="interaction_manual",
            ended_at="2026-07-01T10:30:00Z",
        ),
    ]

    recommendation = subject.recommend_paper_freeze_for_runs(
        "com.cnn.mobile.android.phone",
        runs,
        active_identity=("19250507", "e" * 64),
    )

    assert recommendation.selected_build is not None
    assert recommendation.selected_build.version_code == "19250507"
    assert recommendation.selected_build.static_run_ids == ("4911", "5093", "5389", "5563")
    assert recommendation.selected_build.strict_idle_runs == 3
    assert recommendation.selected_build.quiescent_fg_runs == 0
    assert recommendation.selected_build.baseline_valid_runs == 3
    assert recommendation.selected_build.interactive_valid_runs == 4
    assert recommendation.selected_build.status == "ready"
    assert recommendation.refresh_candidate is False


def test_build_paper_freeze_manifest_emits_plan_rows(monkeypatch) -> None:
    monkeypatch.setattr(subject, "active_research_cohort_packages", lambda: ("com.whatsapp",))
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: (
            "ok",
            {
                "apps": {
                    "com.whatsapp": {
                        "runs": [
                            _run(
                                run_id="wa-b1",
                                version_code="262408020",
                                version_name="2.26.24.80",
                                static_run_id="5700",
                                base_sha="a" * 64,
                                profile="baseline_connected",
                            ),
                            _run(
                                run_id="wa-b2",
                                version_code="262408020",
                                version_name="2.26.24.80",
                                static_run_id="5700",
                                base_sha="a" * 64,
                                profile="baseline_connected",
                            ),
                        ]
                    }
                }
            },
            None,
        ),
    )
    monkeypatch.setattr(subject, "resolve_active_package_identity", lambda package: ("262508000", "b" * 64))

    manifest = subject.build_paper_freeze_manifest()

    assert manifest["cohort_label"] == "Research Dataset Beta"
    assert manifest["summary"]["apps_total"] == 1
    assert manifest["summary"]["needs_baseline"] == 1
    row = manifest["apps"][0]
    assert row["selected_version_code"] == "262408020"
    assert row["selected_relation"] == "prior-build"
    assert row["strict_idle_count"] == 2
    assert row["quiescent_fg_count"] == 0
    assert row["refresh_candidate"] == "yes"
    assert row["selected_static_run_ids"] == "5700"
    assert row["status"] == "needs baseline"
    plan = manifest["paper_minimal_run_plan"][0]
    assert plan["recommended_next_action"] == "baseline"
    assert plan["paper_target_static_run_ids"] == "5700"
    assert plan["strict_idle_count"] == 2
    assert plan["quiescent_fg_count"] == 0
    assert plan["strict_idle_ready"] == "no"


def test_paper_freeze_decision_board_whatsapp_ready_prior_build(monkeypatch) -> None:
    monkeypatch.setattr(subject, "active_research_cohort_packages", lambda: ("com.whatsapp",))
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: (
            "ok",
            {
                "apps": {
                    "com.whatsapp": {
                        "runs": [
                            _run(run_id="wa-b1", version_code="262408020", version_name="2.26.24.80", static_run_id="5700", base_sha="a" * 64, profile="baseline_connected"),
                            _run(run_id="wa-b2", version_code="262408020", version_name="2.26.24.80", static_run_id="5700", base_sha="a" * 64, profile="baseline_connected"),
                            _run(run_id="wa-b3", version_code="262408020", version_name="2.26.24.80", static_run_id="5700", base_sha="a" * 64, profile="baseline_connected"),
                            _run(run_id="wa-i1", version_code="262408020", version_name="2.26.24.80", static_run_id="5700", base_sha="a" * 64, profile="interaction_manual"),
                            _run(run_id="wa-i2", version_code="262408020", version_name="2.26.24.80", static_run_id="5700", base_sha="a" * 64, profile="interaction_manual"),
                            _run(run_id="wa-i3", version_code="262408020", version_name="2.26.24.80", static_run_id="5700", base_sha="a" * 64, profile="interaction_scripted"),
                            _run(run_id="wa-i4", version_code="262408020", version_name="2.26.24.80", static_run_id="5700", base_sha="a" * 64, profile="interaction_manual"),
                            _run(run_id="wa-i5", version_code="262408020", version_name="2.26.24.80", static_run_id="5700", base_sha="a" * 64, profile="interaction_manual"),
                        ]
                    }
                }
            },
            None,
        ),
    )
    monkeypatch.setattr(subject, "resolve_active_package_identity", lambda package: ("262508000", "b" * 64))

    board = subject.build_paper_freeze_decision_board()
    row = board["rows"][0]

    assert row["bucket"] == "READY_DO_NOT_TOUCH"
    assert row["strict_idle_count"] == 3
    assert row["quiescent_fg_count"] == 0
    assert row["draft_role"] == "ready_coverage"
    assert row["collectability"] == "ready_prior_build"
    assert row["rough_draft_blocker"] == "no"


def test_paper_freeze_decision_board_current_interactive_gap_is_optional_depth(monkeypatch) -> None:
    monkeypatch.setattr(subject, "active_research_cohort_packages", lambda: ("org.reddit.frontpage",))
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: (
            "ok",
            {
                "apps": {
                    "org.reddit.frontpage": {
                        "runs": [
                            _run(run_id="rd-b1", version_code="300", version_name="2026.26", static_run_id="6101", base_sha="r" * 64, profile="baseline_idle"),
                            _run(run_id="rd-b2", version_code="300", version_name="2026.26", static_run_id="6101", base_sha="r" * 64, profile="baseline_idle"),
                            _run(run_id="rd-b3", version_code="300", version_name="2026.26", static_run_id="6101", base_sha="r" * 64, profile="baseline_idle"),
                            _run(run_id="rd-i1", version_code="300", version_name="2026.26", static_run_id="6101", base_sha="r" * 64, profile="interaction_manual"),
                        ]
                    }
                }
            },
            None,
        ),
    )
    monkeypatch.setattr(subject, "resolve_active_package_identity", lambda package: ("300", "r" * 64))

    board = subject.build_paper_freeze_decision_board()
    row = board["rows"][0]

    assert row["bucket"] == "RUN_ONLY_IF_EASY"
    assert row["strict_idle_count"] == 3
    assert row["quiescent_fg_count"] == 0
    assert row["draft_role"] == "interactive_depth_gap"
    assert row["collectability"] == "optional_current_depth"
    assert row["action"] == "interactive if claim needs it"
    assert row["rough_draft_blocker"] == "no"
    assert "do not block the rough draft" in row["reason"]


def test_paper_freeze_decision_board_current_baseline_gap_stays_must_run_now(monkeypatch) -> None:
    monkeypatch.setattr(subject, "active_research_cohort_packages", lambda: ("org.reddit.frontpage",))
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: (
            "ok",
            {
                "apps": {
                    "org.reddit.frontpage": {
                        "runs": [
                            _run(run_id="rd-b1", version_code="300", version_name="2026.26", static_run_id="6101", base_sha="r" * 64, profile="baseline_idle"),
                            _run(run_id="rd-i1", version_code="300", version_name="2026.26", static_run_id="6101", base_sha="r" * 64, profile="interaction_manual"),
                        ]
                    }
                }
            },
            None,
        ),
    )
    monkeypatch.setattr(subject, "resolve_active_package_identity", lambda package: ("300", "r" * 64))

    board = subject.build_paper_freeze_decision_board()
    row = board["rows"][0]

    assert row["bucket"] == "MUST_RUN_NOW"
    assert row["draft_role"] == "current_gap"
    assert row["collectability"] == "collectable_now"
    assert row["action"] == "baseline"
    assert row["rough_draft_blocker"] == "yes"
    assert "missing baseline evidence" in row["reason"]


def test_paper_freeze_decision_board_switch_target_candidate(monkeypatch) -> None:
    monkeypatch.setattr(subject, "active_research_cohort_packages", lambda: ("com.twitter.android",))
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: (
            "ok",
            {
                "apps": {
                        "com.twitter.android": {
                            "runs": [
                                _run(run_id="x-old-b1", version_code="312041000", version_name="12.4.1", static_run_id="6200", base_sha="x" * 64, profile="baseline_idle"),
                                _run(run_id="x-old-b2", version_code="312041000", version_name="12.4.1", static_run_id="6200", base_sha="x" * 64, profile="baseline_idle"),
                                _run(run_id="x-old-b3", version_code="312041000", version_name="12.4.1", static_run_id="6200", base_sha="x" * 64, profile="baseline_idle"),
                                _run(run_id="x-old-i1", version_code="312041000", version_name="12.4.1", static_run_id="6200", base_sha="x" * 64, profile="interaction_manual"),
                                _run(run_id="x-cur-b1", version_code="312050000", version_name="12.5.0", static_run_id="6300", base_sha="y" * 64, profile="baseline_idle"),
                                _run(run_id="x-cur-b2", version_code="312050000", version_name="12.5.0", static_run_id="6300", base_sha="y" * 64, profile="baseline_idle"),
                                _run(run_id="x-cur-b3", version_code="312050000", version_name="12.5.0", static_run_id="6300", base_sha="y" * 64, profile="baseline_idle"),
                            ]
                        }
                }
            },
            None,
        ),
    )
    monkeypatch.setattr(subject, "resolve_active_package_identity", lambda package: ("312050000", "y" * 64))

    board = subject.build_paper_freeze_decision_board()
    row = board["rows"][0]

    assert row["bucket"] == "SWITCH_TARGET_CANDIDATE"
    assert row["draft_role"] == "target_decision"
    assert row["collectability"] == "switch_target_candidate"
    assert row["rough_draft_blocker"] == "no"


def test_paper_freeze_decision_board_no_selected_target_defers(monkeypatch) -> None:
    monkeypatch.setattr(subject, "active_research_cohort_packages", lambda: ("org.thoughtcrime.securesms",))
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: ("ok", {"apps": {"org.thoughtcrime.securesms": {"runs": []}}}, None),
    )
    monkeypatch.setattr(subject, "resolve_active_package_identity", lambda package: ("", ""))

    board = subject.build_paper_freeze_decision_board()
    row = board["rows"][0]

    assert row["bucket"] == "DEFER_REFRESH_WAVE"
    assert row["draft_role"] == "deferred"
    assert row["collectability"] == "not_selected"
    assert row["rough_draft_blocker"] == "no"


def test_paper_freeze_keeps_quiescent_fg_separate_from_strict_idle(monkeypatch) -> None:
    monkeypatch.setattr(subject, "active_research_cohort_packages", lambda: ("com.zhiliaoapp.musically",))
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: (
            "ok",
            {
                "apps": {
                    "com.zhiliaoapp.musically": {
                        "runs": [
                            _run(
                                run_id=f"tt-q{i}",
                                version_code="2024507030",
                                version_name="45.7.3",
                                static_run_id="5838",
                                base_sha="t" * 64,
                                profile="baseline_idle",
                                baseline_not_idle=True,
                            )
                            for i in range(1, 8)
                        ]
                        + [
                            _run(
                                run_id="tt-i1",
                                version_code="2024507030",
                                version_name="45.7.3",
                                static_run_id="5838",
                                base_sha="t" * 64,
                                profile="interaction_manual",
                            ),
                            _run(
                                run_id="tt-i2",
                                version_code="2024507030",
                                version_name="45.7.3",
                                static_run_id="5838",
                                base_sha="t" * 64,
                                profile="interaction_manual",
                            ),
                        ],
                    }
                }
            },
            None,
        ),
    )
    monkeypatch.setattr(subject, "resolve_active_package_identity", lambda package: ("2024507030", "t" * 64))

    manifest = subject.build_paper_freeze_manifest()
    row = manifest["apps"][0]
    assert row["selected_version_code"] == "2024507030"
    assert row["strict_idle_count"] == 0
    assert row["quiescent_fg_count"] == 7
    assert row["interactive_count"] == 2
    assert row["strict_idle_ready"] == "no"
    assert row["quiescent_fg_available"] == "yes"
    assert row["strict_workflow_blocked"] == "yes"
    assert row["status"] == "needs interactive"
    assert "does not satisfy strict-idle" in row["baseline_class_note"]

    board = subject.build_paper_freeze_decision_board()
    board_row = board["rows"][0]
    assert board_row["bucket"] == "RUN_ONLY_IF_EASY"
    assert board_row["strict_idle_count"] == 0
    assert board_row["quiescent_fg_count"] == 7
    assert board_row["interactive_count"] == 2
    assert board_row["strict_idle_ready"] == "no"
    assert board_row["strict_workflow_blocked"] == "yes"
    assert board_row["strict_workflow_status"] == "strict idle gap"
    assert board_row["action"] == "interactive if claim needs it"
    assert board_row["rough_draft_blocker"] == "no"
    assert "do not block the rough draft" in board_row["reason"]
    plan = manifest["paper_minimal_run_plan"][0]
    assert plan["strict_idle_count"] == 0
    assert plan["quiescent_fg_count"] == 7
    assert plan["strict_idle_ready"] == "no"
    assert plan["strict_workflow_blocked"] == "yes"
    assert plan["strict_workflow_status"] == "strict idle gap"
    assert plan["recommended_next_action"] == "strict idle retry"
    assert "does not satisfy strict-idle" in plan["baseline_class_note"]


def test_paper_freeze_reddit_like_row_counts_baseline_and_separate_qfg(monkeypatch) -> None:
    monkeypatch.setattr(subject, "active_research_cohort_packages", lambda: ("org.reddit.frontpage",))
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: (
            "ok",
            {
                "apps": {
                    "org.reddit.frontpage": {
                        "runs": [
                            _run(
                                run_id="rd-s1",
                                version_code="300",
                                version_name="2026.26",
                                static_run_id="6101",
                                base_sha="r" * 64,
                                profile="baseline_idle",
                            ),
                            _run(
                                run_id="rd-s2",
                                version_code="300",
                                version_name="2026.26",
                                static_run_id="6101",
                                base_sha="r" * 64,
                                profile="baseline_idle",
                            ),
                            _run(
                                run_id="rd-q1",
                                version_code="300",
                                version_name="2026.26",
                                static_run_id="6101",
                                base_sha="r" * 64,
                                profile="baseline_idle",
                                baseline_not_idle=True,
                            ),
                            _run(
                                run_id="rd-q2",
                                version_code="300",
                                version_name="2026.26",
                                static_run_id="6101",
                                base_sha="r" * 64,
                                profile="baseline_idle",
                                baseline_not_idle=True,
                            ),
                            _run(
                                run_id="rd-q3",
                                version_code="300",
                                version_name="2026.26",
                                static_run_id="6101",
                                base_sha="r" * 64,
                                profile="baseline_idle",
                                baseline_not_idle=True,
                            ),
                        ]
                    }
                }
            },
            None,
        ),
    )
    monkeypatch.setattr(subject, "resolve_active_package_identity", lambda package: ("300", "r" * 64))

    manifest = subject.build_paper_freeze_manifest()
    row = manifest["apps"][0]
    assert row["strict_idle_count"] == 2
    assert row["quiescent_fg_count"] == 3
    assert row["baseline_count"] == 5
    assert row["missing_baseline_runs"] == 0
    assert row["status"] == "needs interactive"


def test_paper_evidence_tier_report_classifies_cutoff_bundles(monkeypatch) -> None:
    monkeypatch.setattr(
        subject,
        "active_research_cohort_packages",
        lambda: ("bbc.mobile.news.ww", "com.reddit.frontpage", "com.facebook.katana", "org.telegram.messenger"),
    )
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: (
            "ok",
            {
                "apps": {
                    "bbc.mobile.news.ww": {
                        "runs": [
                            _run(run_id=f"bbc-b{i}", version_code="100", version_name="1.0", static_run_id="1", base_sha="b" * 64, profile="baseline_idle")
                            for i in range(1, 4)
                        ]
                        + [
                            _run(run_id=f"bbc-i{i}", version_code="100", version_name="1.0", static_run_id="1", base_sha="b" * 64, profile="interaction_manual")
                            for i in range(1, 5)
                        ]
                    },
                    "com.reddit.frontpage": {
                        "runs": [
                            _run(run_id="rd-s1", version_code="300", version_name="2026.26", static_run_id="2", base_sha="r" * 64, profile="baseline_idle"),
                            _run(run_id="rd-s2", version_code="300", version_name="2026.26", static_run_id="2", base_sha="r" * 64, profile="baseline_idle"),
                            _run(run_id="rd-q1", version_code="300", version_name="2026.26", static_run_id="2", base_sha="r" * 64, profile="baseline_idle", baseline_not_idle=True),
                            _run(run_id="rd-q2", version_code="300", version_name="2026.26", static_run_id="2", base_sha="r" * 64, profile="baseline_idle", baseline_not_idle=True),
                            _run(run_id="rd-q3", version_code="300", version_name="2026.26", static_run_id="2", base_sha="r" * 64, profile="baseline_idle", baseline_not_idle=True),
                        ]
                    },
                    "com.facebook.katana": {
                        "runs": [
                            _run(run_id=f"fb-b{i}", version_code="200", version_name="2.0", static_run_id="3", base_sha="f" * 64, profile="baseline_idle")
                            for i in range(1, 4)
                        ]
                        + [
                            _run(run_id=f"fb-i{i}", version_code="200", version_name="2.0", static_run_id="3", base_sha="f" * 64, profile="interaction_manual")
                            for i in range(1, 5)
                        ]
                    },
                    "org.telegram.messenger": {"runs": []},
                }
            },
            None,
        ),
    )

    def active_identity(package: str) -> tuple[str, str]:
        return {
            "bbc.mobile.news.ww": ("100", "b" * 64),
            "com.reddit.frontpage": ("300", "r" * 64),
            "com.facebook.katana": ("201", "x" * 64),
            "org.telegram.messenger": ("400", "t" * 64),
        }[package]

    monkeypatch.setattr(subject, "resolve_active_package_identity", active_identity)

    report = subject.build_paper_evidence_tier_report(
        live_drift_map={
            "bbc.mobile.news.ww": {"observed_version_code": "101"},
            "com.facebook.katana": {"observed_version_code": "202"},
        }
    )
    rows = {row["package_name"]: row for row in report["rows"]}

    assert rows["bbc.mobile.news.ww"]["evidence_tier"] == "STRICT_CURRENT_BUILD_COMPLETE"
    assert rows["bbc.mobile.news.ww"]["paper_usable"] == "yes"
    assert rows["bbc.mobile.news.ww"]["operational_live_drifted"] == "yes"
    assert rows["bbc.mobile.news.ww"]["operational_installed_version_code"] == "101"
    assert rows["com.reddit.frontpage"]["evidence_tier"] == "CURRENT_BUILD_MIXED_BASELINE"
    assert rows["com.reddit.frontpage"]["strict_idle_count"] == 2
    assert rows["com.reddit.frontpage"]["quiescent_fg_count"] == 3
    assert rows["com.reddit.frontpage"]["paper_usable"] == "yes"
    assert rows["com.facebook.katana"]["evidence_tier"] == "PRIOR_BUILD_PAPER_EVIDENCE"
    assert rows["com.facebook.katana"]["current_installed_drifted"] == "yes"
    assert rows["com.facebook.katana"]["operational_live_drifted"] == "yes"
    assert rows["org.telegram.messenger"]["evidence_tier"] == "TRUE_EVIDENCE_HOLE"
    assert rows["org.telegram.messenger"]["paper_usable"] == "no"
    assert report["summary"]["tier_counts"] == {
        "CURRENT_BUILD_MIXED_BASELINE": 1,
        "PRIOR_BUILD_PAPER_EVIDENCE": 1,
        "STRICT_CURRENT_BUILD_COMPLETE": 1,
        "TRUE_EVIDENCE_HOLE": 1,
    }
    assert report["summary"]["drifted_but_paper_usable"] == 2


def test_paper_evidence_tier_report_skip_live_drift_does_not_claim_operational_drift(
    monkeypatch,
) -> None:
    monkeypatch.setattr(subject, "active_research_cohort_packages", lambda: ("com.facebook.katana",))
    monkeypatch.setattr(subject, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(
        subject,
        "_load_tracker_payload",
        lambda cfg: (
            "ok",
            {
                "apps": {
                    "com.facebook.katana": {
                        "runs": [
                            _run(
                                run_id=f"fb-b{i}",
                                version_code="200",
                                version_name="2.0",
                                static_run_id="3",
                                base_sha="f" * 64,
                                profile="baseline_idle",
                            )
                            for i in range(1, 4)
                        ]
                    }
                }
            },
            None,
        ),
    )
    monkeypatch.setattr(subject, "resolve_active_package_identity", lambda package: ("201", "x" * 64))

    report = subject.build_paper_evidence_tier_report(live_drift_map=None)
    row = report["rows"][0]

    assert row["evidence_tier"] == "PRIOR_BUILD_PAPER_EVIDENCE"
    assert row["paper_usable"] == "yes"
    assert row["current_installed_drifted"] == "yes"
    assert row["operational_live_drifted"] == "not_checked"
    assert row["operational_installed_version_code"] == ""
    assert "not checked" in row["operational_drift_detail"]
    assert report["summary"]["live_drift_checked"] is False
    assert report["summary"]["drifted_but_paper_usable"] == 0
    assert report["summary"]["prior_build_paper_usable"] == 1
