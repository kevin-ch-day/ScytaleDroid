from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap import interaction_phases
from tests.dynamic._interaction_phase_support import (
    news_events,
    scripted_manifest,
    write_json,
    write_jsonl,
)


def test_build_interaction_timeline_from_run_dir_complete(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = scripted_manifest("run-1", "bbc.mobile.news.ww")
    write_json(run_dir / "run_manifest.json", manifest)
    write_jsonl(run_dir / "notes" / "run_events.jsonl", news_events())

    timeline = interaction_phases.build_interaction_timeline_from_run_dir(run_dir)

    assert timeline is not None
    assert timeline["template_id"] == "news_reader_basic_v1"
    assert timeline["planned_step_count"] == 6
    assert timeline["completed_step_count"] == 6
    assert timeline["timeline_complete"] is True
    assert len(timeline["steps"]) == 6
    assert timeline["steps"][0]["phase_label"] == "Open Home"
    assert timeline["steps"][0]["operator_completed"] is True


def test_build_interaction_timeline_marks_missing_step_end(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = scripted_manifest("run-2", "bbc.mobile.news.ww")
    write_json(run_dir / "run_manifest.json", manifest)
    write_jsonl(run_dir / "notes" / "run_events.jsonl", news_events(missing_step_end=True))

    timeline = interaction_phases.build_interaction_timeline_from_run_dir(run_dir)

    assert timeline is not None
    assert timeline["timeline_complete"] is False
    assert "step_count_incomplete" in timeline["limitations"]
    assert any(
        item.startswith("missing_step_end:2:scroll_headlines") for item in timeline["limitations"]
    )
    second_step = timeline["steps"][1]
    assert second_step["actual_end_timestamp"] is None
    assert "missing_step_end" in second_step["notes"]


def test_build_interaction_timeline_preserves_limited_step_details(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = scripted_manifest("run-limited", "com.cnn.mobile.android.phone")
    write_json(run_dir / "run_manifest.json", manifest)
    rows = news_events()
    for row in rows:
        if row.get("event_type") == "STEP_END":
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            if details.get("step_index") == 3:
                details["step_outcome"] = "limited"
                details["limitation_reason"] = "paywall"
                details["operator_note"] = "hit subscription wall"
                break
    write_jsonl(run_dir / "notes" / "run_events.jsonl", rows)

    timeline = interaction_phases.build_interaction_timeline_from_run_dir(run_dir)

    assert timeline is not None
    assert timeline["timeline_complete"] is True
    step = timeline["steps"][2]
    assert step["step_outcome"] == "limited"
    assert step["limitation_reason"] == "paywall"
    assert step["operator_note"] == "hit subscription wall"
    assert step["operator_completed"] is True
    assert "limitation=paywall" in step["notes"]


def test_build_interaction_timeline_preserves_control_account_metadata(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = scripted_manifest("run-fb", "com.facebook.katana")
    manifest["scenario"]["id"] = "basic_usage"
    manifest["operator"].update(
        {
            "template_id": "facebook_behavior_v3",
            "template_hash": "fbhash",
            "template_map_version": "v1+overrides:v1",
            "step_count_planned": 1,
        }
    )
    write_json(run_dir / "run_manifest.json", manifest)
    write_jsonl(
        run_dir / "notes" / "run_events.jsonl",
        [
            {
                "timestamp": "2026-06-15T12:00:00Z",
                "event_type": "SCRIPT_START",
                "details": {
                    "template_id": "facebook_behavior_v3",
                    "template_hash": "fbhash",
                    "template_map_version": "v1+overrides:v1",
                    "step_count_planned": 1,
                    "account_context": "control_test_account",
                    "control_account": True,
                    "control_account_mode": "control_account_active",
                    "mutation_allowed": True,
                    "cleanup_expected": True,
                },
            },
            {
                "timestamp": "2026-06-15T12:00:01Z",
                "event_type": "STEP_START",
                "details": {
                    "step_id": "text_post_submit_1",
                    "step_index": 1,
                    "expected_duration_s": 30,
                    "account_context": "control_test_account",
                    "control_account": True,
                    "control_account_mode": "control_account_active",
                    "mutation_allowed": True,
                    "cleanup_expected": True,
                    "mutation_candidate": True,
                    "repeat_group": "text_post_submit",
                    "repeat_index": 1,
                    "repeat_total": 3,
                    "repeat_max_total": 3,
                    "repeat_enabled": True,
                },
            },
            {
                "timestamp": "2026-06-15T12:00:05Z",
                "event_type": "PHASE_MARKER",
                "details": {
                    "step_id": "text_post_submit_1",
                    "step_index": 1,
                    "phase_id": "return_home_manual",
                    "phase_label": "Return Home Manual",
                    "operator_result": "done",
                    "account_context": "control_test_account",
                    "control_account": True,
                    "control_account_mode": "control_account_active",
                    "mutation_allowed": True,
                    "cleanup_expected": True,
                    "mutation_performed": False,
                    "repeat_group": "text_post_submit",
                    "repeat_index": 1,
                    "repeat_total": 3,
                    "repeat_max_total": 3,
                    "repeat_enabled": True,
                },
            },
            {
                "timestamp": "2026-06-15T12:00:31Z",
                "event_type": "STEP_END",
                "details": {
                    "step_id": "text_post_submit_1",
                    "step_index": 1,
                    "expected_duration_s": 30,
                    "elapsed_s": 30.0,
                    "step_outcome": "completed",
                    "operator_result": "completed",
                    "account_context": "control_test_account",
                    "control_account": True,
                    "control_account_mode": "control_account_active",
                    "mutation_allowed": True,
                    "cleanup_expected": True,
                    "mutation_candidate": True,
                    "mutation_performed": True,
                    "repeat_group": "text_post_submit",
                    "repeat_index": 1,
                    "repeat_total": 3,
                    "repeat_max_total": 3,
                    "repeat_enabled": True,
                },
            },
            {
                "timestamp": "2026-06-15T12:00:32Z",
                "event_type": "SCRIPT_END",
                "details": {
                    "template_id": "facebook_behavior_v3",
                    "template_hash": "fbhash",
                    "template_map_version": "v1+overrides:v1",
                    "step_count_planned": 1,
                    "step_count_completed": 1,
                },
            },
        ],
    )

    timeline = interaction_phases.build_interaction_timeline_from_run_dir(run_dir)

    assert timeline is not None
    step = timeline["steps"][0]
    assert step["account_context"] == "control_test_account"
    assert step["control_account"] is True
    assert step["control_account_mode"] == "control_account_active"
    assert step["mutation_performed"] is True
    assert step["repeat_group"] == "text_post_submit"
    assert step["repeat_index"] == 1
    assert step["repeat_total"] == 3
    assert step["repeat_enabled"] is True
    assert timeline["phase_markers"][0]["phase_id"] == "return_home_manual"
    assert timeline["phase_markers"][0]["mutation_performed"] is False


def test_build_interaction_timeline_preserves_news_subscription_branch_metadata(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    manifest = scripted_manifest("run-news", "bbc.mobile.news.ww")
    manifest["operator"].update(
        {
            "template_id": "news_reader_behavior_v2",
            "template_hash": "newshash",
            "template_map_version": "v1",
            "step_count_planned": 2,
        }
    )
    write_json(run_dir / "run_manifest.json", manifest)
    write_jsonl(
        run_dir / "notes" / "run_events.jsonl",
        [
            {
                "timestamp": "2026-06-15T12:00:00Z",
                "event_type": "SCRIPT_START",
                "details": {
                    "template_id": "news_reader_behavior_v2",
                    "template_hash": "newshash",
                    "template_map_version": "v1",
                    "step_count_planned": 2,
                },
            },
            {
                "timestamp": "2026-06-15T12:00:01Z",
                "event_type": "STEP_START",
                "details": {
                    "step_id": "open_article",
                    "step_index": 1,
                    "expected_duration_s": 30,
                },
            },
            {
                "timestamp": "2026-06-15T12:00:31Z",
                "event_type": "STEP_END",
                "details": {
                    "step_id": "open_article",
                    "step_index": 1,
                    "expected_duration_s": 30,
                    "elapsed_s": 30.0,
                    "step_outcome": "limited",
                    "operator_result": "limited",
                    "limitation_reason": "subscription_required",
                    "branch_taken": "subscription_required",
                    "article_branch": "subscription_required",
                    "subscription_wall_observed": False,
                    "subscription_options_opened": False,
                    "return_home_performed": False,
                    "protocol_fit": "limited_but_compliant",
                },
            },
            {
                "timestamp": "2026-06-15T12:00:31Z",
                "event_type": "STEP_START",
                "details": {
                    "step_id": "subscription_wall_observe",
                    "step_index": 2,
                    "expected_duration_s": 30,
                    "branch_taken": "subscription_required",
                    "article_branch": "subscription_required",
                    "subscription_wall_observed": True,
                    "subscription_options_opened": False,
                    "return_home_performed": False,
                    "protocol_fit": "limited_but_compliant",
                },
            },
            {
                "timestamp": "2026-06-15T12:01:01Z",
                "event_type": "STEP_END",
                "details": {
                    "step_id": "subscription_wall_observe",
                    "step_index": 2,
                    "expected_duration_s": 30,
                    "elapsed_s": 30.0,
                    "step_outcome": "completed",
                    "operator_result": "completed",
                    "branch_taken": "subscription_required",
                    "article_branch": "subscription_required",
                    "subscription_wall_observed": True,
                    "subscription_options_opened": False,
                    "return_home_performed": False,
                    "protocol_fit": "limited_but_compliant",
                },
            },
            {
                "timestamp": "2026-06-15T12:01:02Z",
                "event_type": "SCRIPT_END",
                "details": {
                    "template_id": "news_reader_behavior_v2",
                    "template_hash": "newshash",
                    "template_map_version": "v1",
                    "step_count_planned": 2,
                    "step_count_completed": 2,
                    "article_branch": "subscription_required",
                    "protocol_fit": "limited_but_compliant",
                },
            },
        ],
    )

    timeline = interaction_phases.build_interaction_timeline_from_run_dir(run_dir)
    rows = interaction_phases.build_protocol_phase_marker_rows(timeline or {})

    assert timeline is not None
    assert timeline["steps"][0]["article_branch"] == "subscription_required"
    assert timeline["steps"][0]["protocol_fit"] == "limited_but_compliant"
    assert timeline["steps"][1]["subscription_wall_observed"] is True
    assert rows[1]["phase_id"] == "subscription_wall_observe"
    assert rows[1]["subscription_wall_observed"] is True
    assert rows[1]["protocol_fit"] == "limited_but_compliant"


def test_non_scripted_run_omits_timeline(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = scripted_manifest("run-3", "bbc.mobile.news.ww")
    manifest["operator"]["run_profile"] = "interaction_manual"
    write_json(run_dir / "run_manifest.json", manifest)

    timeline = interaction_phases.build_interaction_timeline_from_run_dir(run_dir)

    assert timeline is None
