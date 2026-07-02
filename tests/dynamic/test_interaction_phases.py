from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap import interaction_phases
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.scenarios.manual_templates import template_steps_for_id


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def _scripted_manifest(run_id: str, package: str) -> dict[str, object]:
    return {
        "dynamic_run_id": run_id,
        "started_at": "2026-06-15T12:00:00Z",
        "target": {"package_name": package, "display_name": "BBC News"},
        "scenario": {"id": "paper3_profile_v3"},
        "operator": {
            "run_profile": "interaction_scripted",
            "interaction_level": "scripted",
            "template_id": "news_reader_basic_v1",
            "template_hash": "abc123",
            "template_map_version": "v1",
            "step_count_planned": 6,
        },
        "artifacts": [
            {
                "relative_path": "artifacts/pcapdroid_capture/app.pcap",
                "type": "pcapdroid_capture",
                "produced_by": "pcapdroid_capture",
            }
        ],
    }


def _news_events(*, missing_step_end: bool = False) -> list[dict[str, object]]:
    steps = template_steps_for_id("news_reader_basic_v1")
    assert steps is not None
    rows: list[dict[str, object]] = [
        {
            "timestamp": "2026-06-15T12:00:00Z",
            "event_type": "SCRIPT_START",
            "details": {
                "template_id": "news_reader_basic_v1",
                "template_hash": "abc123",
                "template_map_version": "v1",
                "step_count_planned": len(steps),
            },
        }
    ]
    second = 0
    for idx, (step_id, _prompt, expected) in enumerate(steps, start=1):
        start_s = second
        end_s = second + expected
        rows.append(
            {
                "timestamp": f"2026-06-15T12:{start_s // 60:02d}:{start_s % 60:02d}Z",
                "event_type": "STEP_START",
                "details": {
                    "step_id": step_id,
                    "step_index": idx,
                    "expected_duration_s": expected,
                    "step_variant": None,
                },
            }
        )
        if not (missing_step_end and idx == 2):
            rows.append(
                {
                    "timestamp": f"2026-06-15T12:{end_s // 60:02d}:{end_s % 60:02d}Z",
                    "event_type": "STEP_END",
                    "details": {
                        "step_id": step_id,
                        "step_index": idx,
                        "expected_duration_s": expected,
                        "elapsed_s": float(expected),
                        "step_variant": None,
                        "step_outcome": "completed",
                    },
                }
            )
        second = end_s
    rows.append(
        {
            "timestamp": f"2026-06-15T12:{second // 60:02d}:{second % 60:02d}Z",
            "event_type": "SCRIPT_END",
            "details": {
                "template_id": "news_reader_basic_v1",
                "template_hash": "abc123",
                "template_map_version": "v1",
                "step_count_planned": len(steps),
                "step_count_completed": len(steps) - (1 if missing_step_end else 0),
            },
        }
    )
    return rows


def test_build_interaction_timeline_from_run_dir_complete(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = _scripted_manifest("run-1", "bbc.mobile.news.ww")
    _write_json(run_dir / "run_manifest.json", manifest)
    _write_jsonl(run_dir / "notes" / "run_events.jsonl", _news_events())

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
    manifest = _scripted_manifest("run-2", "bbc.mobile.news.ww")
    _write_json(run_dir / "run_manifest.json", manifest)
    _write_jsonl(run_dir / "notes" / "run_events.jsonl", _news_events(missing_step_end=True))

    timeline = interaction_phases.build_interaction_timeline_from_run_dir(run_dir)

    assert timeline is not None
    assert timeline["timeline_complete"] is False
    assert "step_count_incomplete" in timeline["limitations"]
    assert any(item.startswith("missing_step_end:2:scroll_headlines") for item in timeline["limitations"])
    second_step = timeline["steps"][1]
    assert second_step["actual_end_timestamp"] is None
    assert "missing_step_end" in second_step["notes"]


def test_build_interaction_timeline_preserves_limited_step_details(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = _scripted_manifest("run-limited", "com.cnn.mobile.android.phone")
    _write_json(run_dir / "run_manifest.json", manifest)
    rows = _news_events()
    for row in rows:
        if row.get("event_type") == "STEP_END":
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            if details.get("step_index") == 3:
                details["step_outcome"] = "limited"
                details["limitation_reason"] = "paywall"
                details["operator_note"] = "hit subscription wall"
                break
    _write_jsonl(run_dir / "notes" / "run_events.jsonl", rows)

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
    manifest = _scripted_manifest("run-fb", "com.facebook.katana")
    manifest["scenario"]["id"] = "basic_usage"
    manifest["operator"].update(
        {
            "template_id": "facebook_behavior_v3",
            "template_hash": "fbhash",
            "template_map_version": "v1+overrides:v1",
            "step_count_planned": 1,
        }
    )
    _write_json(run_dir / "run_manifest.json", manifest)
    _write_jsonl(
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


def test_build_interaction_timeline_preserves_news_subscription_branch_metadata(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = _scripted_manifest("run-news", "bbc.mobile.news.ww")
    manifest["operator"].update(
        {
            "template_id": "news_reader_behavior_v2",
            "template_hash": "newshash",
            "template_map_version": "v1",
            "step_count_planned": 2,
        }
    )
    _write_json(run_dir / "run_manifest.json", manifest)
    _write_jsonl(
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


def test_protocol_phase_marker_rows_flatten_steps_and_manual_markers(tmp_path: Path) -> None:
    timeline = {
        "run_id": "run-fb",
        "package": "com.facebook.katana",
        "scenario_id": "basic_usage",
        "template_id": "facebook_behavior_v3",
        "template_hash": "fbhash",
        "mapping_version": "v1+overrides:v1",
        "steps": [
            {
                "step_id": "text_post_submit_1",
                "step_index": 1,
                "phase_label": "Text Post Submit 1",
                "actual_start_timestamp": "2026-06-15T12:00:01Z",
                "actual_end_timestamp": "2026-06-15T12:00:31Z",
                "planned_duration_sec": 30,
                "actual_duration_sec": 30.0,
                "operator_result": "completed",
                "step_outcome": "completed",
                "account_context": "control_test_account",
                "control_account": True,
                "control_account_mode": "control_account_active",
                "mutation_allowed": True,
                "mutation_candidate": True,
                "mutation_performed": True,
                "cleanup_expected": True,
                "repeat_group": "text_post_submit",
                "repeat_index": 1,
                "repeat_total": 3,
                "repeat_max_total": 3,
                "repeat_enabled": True,
            }
        ],
        "phase_markers": [
            {
                "timestamp": "2026-06-15T12:00:05Z",
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
            }
        ],
    }

    rows = interaction_phases.build_protocol_phase_marker_rows(timeline)

    assert len(rows) == 2
    assert rows[0]["marker_type"] == "step_window"
    assert rows[0]["phase_id"] == "text_post_submit_1"
    assert rows[0]["mutation_performed"] is True
    assert rows[0]["repeat_group"] == "text_post_submit"
    assert rows[0]["repeat_enabled"] is True
    assert rows[1]["marker_type"] == "operator_marker"
    assert rows[1]["phase_id"] == "return_home_manual"
    assert rows[1]["start_time"] == "2026-06-15T12:00:05Z"
    assert rows[1]["mutation_performed"] is False


def test_protocol_phase_marker_rows_include_whatsapp_message_metadata() -> None:
    timeline = {
        "run_id": "run-wa",
        "package": "com.whatsapp",
        "scenario_id": "basic_usage",
        "template_id": "whatsapp_text_behavior_v2",
        "template_hash": "wahash",
        "mapping_version": "v1+overrides:v1",
        "steps": [
            {
                "step_id": "send_text_1",
                "step_index": 3,
                "phase_label": "Send Text 1",
                "actual_start_timestamp": "2026-07-01T06:02:30Z",
                "actual_end_timestamp": "2026-07-01T06:02:45Z",
                "planned_duration_sec": 15,
                "actual_duration_sec": 15.0,
                "operator_result": "completed",
                "step_outcome": "completed",
                "message_type": "text",
                "traffic_phase": "text_send",
                "repeat_group": "text_message",
                "repeat_index": 1,
                "repeat_total": 3,
                "repeat_max_total": 3,
                "repeat_enabled": True,
            }
        ],
        "phase_markers": [
            {
                "timestamp": "2026-07-01T06:02:36Z",
                "step_id": "send_text_1",
                "step_index": 3,
                "phase_id": "return_home_manual",
                "phase_label": "Return Home Manual",
                "operator_result": "done",
                "message_type": "text",
                "traffic_phase": "text_send",
                "repeat_group": "text_message",
                "repeat_index": 1,
                "repeat_total": 3,
                "repeat_max_total": 3,
                "repeat_enabled": True,
            }
        ],
    }

    rows = interaction_phases.build_protocol_phase_marker_rows(timeline)

    assert rows[0]["marker_type"] == "step_window"
    assert rows[0]["message_type"] == "text"
    assert rows[0]["traffic_phase"] == "text_send"
    assert rows[0]["repeat_index"] == 1
    assert rows[1]["marker_type"] == "operator_marker"
    assert rows[1]["message_type"] == "text"
    assert rows[1]["traffic_phase"] == "text_send"


def test_write_protocol_phase_markers_artifact(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = _scripted_manifest("run-fb", "com.facebook.katana")
    _write_json(run_dir / "run_manifest.json", manifest)
    _write_json(
        run_dir / "analysis" / "interaction_timeline.json",
        {
            "run_id": "run-fb",
            "package": "com.facebook.katana",
            "scenario_id": "basic_usage",
            "template_id": "facebook_behavior_v3",
            "template_hash": "fbhash",
            "mapping_version": "v1+overrides:v1",
            "steps": [
                {
                    "step_id": "home_feed",
                    "step_index": 1,
                    "phase_label": "Home Feed",
                    "actual_start_timestamp": "2026-06-15T12:00:00Z",
                    "actual_end_timestamp": "2026-06-15T12:00:30Z",
                    "operator_result": "completed",
                }
            ],
            "phase_markers": [],
        },
    )
    writer = EvidencePackWriter(run_dir)

    artifact = interaction_phases.write_protocol_phase_markers_artifact(
        writer=writer,
        manifest=manifest,
    )

    assert artifact is not None
    assert artifact.relative_path == interaction_phases.PROTOCOL_PHASE_MARKERS_RELATIVE_PATH
    assert artifact.type == "protocol_phase_markers"
    marker_path = run_dir / interaction_phases.PROTOCOL_PHASE_MARKERS_RELATIVE_PATH
    rows = [json.loads(line) for line in marker_path.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["schema_name"] == "scytaledroid.protocol_phase_marker"
    assert rows[0]["phase_id"] == "home_feed"


def test_non_scripted_run_omits_timeline(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = _scripted_manifest("run-3", "bbc.mobile.news.ww")
    manifest["operator"]["run_profile"] = "interaction_manual"
    _write_json(run_dir / "run_manifest.json", manifest)

    timeline = interaction_phases.build_interaction_timeline_from_run_dir(run_dir)

    assert timeline is None


def test_phase_packet_transport_summary_slices_packets_by_step(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run"
    manifest = _scripted_manifest("run-4", "bbc.mobile.news.ww")
    _write_json(run_dir / "run_manifest.json", manifest)
    _write_json(
        run_dir / "analysis" / "interaction_timeline.json",
        {
            "schema_name": "scytaledroid.interaction_timeline",
            "schema_version": "1.1",
            "run_id": "run-4",
            "package": "bbc.mobile.news.ww",
            "run_profile": "interaction_scripted",
            "interaction_level": "scripted",
            "scenario_id": "paper3_profile_v3",
            "template_id": "news_reader_basic_v1",
            "template_hash": "abc123",
            "mapping_version": "v1",
            "script_started_at": "2026-06-15T12:00:00Z",
            "script_ended_at": "2026-06-15T12:01:20Z",
            "planned_step_count": 2,
            "completed_step_count": 2,
            "timeline_complete": True,
            "steps": [
                {
                    "step_index": 1,
                    "step_id": "open_home",
                    "phase_label": "Open Home",
                    "actual_start_timestamp": "2026-06-15T12:00:00Z",
                    "actual_end_timestamp": "2026-06-15T12:00:30Z",
                    "step_outcome": "completed",
                    "limitation_reason": None,
                },
                {
                    "step_index": 2,
                    "step_id": "scroll_headlines",
                    "phase_label": "Scroll Headlines",
                    "actual_start_timestamp": "2026-06-15T12:00:30Z",
                    "actual_end_timestamp": "2026-06-15T12:01:20Z",
                    "step_outcome": "completed",
                    "limitation_reason": None,
                },
            ],
            "limitations": [],
        },
    )
    _write_json(
        run_dir / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json",
        {"capture_start_epoch": 1781524800.0},
    )
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "pcapdroid_capture" / "app.pcap").write_bytes(b"pcap")

    monkeypatch.setattr(
        interaction_phases,
        "extract_phase_packet_timeline",
        lambda _path: [
            interaction_phases.PhasePacketRecord(t=5.0, length=100, protocols="eth:ip:tcp:tls", src_port=50000, dst_port=443),
            interaction_phases.PhasePacketRecord(t=10.0, length=80, protocols="eth:ip:udp:dns", src_port=55555, dst_port=53),
            interaction_phases.PhasePacketRecord(t=40.0, length=120, protocols="eth:ip:udp:quic", src_port=50000, dst_port=443),
            interaction_phases.PhasePacketRecord(t=70.0, length=90, protocols="eth:ip:tcp:tls", src_port=443, dst_port=50000),
        ],
    )

    rows = interaction_phases.phase_packet_transport_summary(run_dir)

    assert len(rows) == 2
    assert rows[0]["packet_count"] == 2
    assert rows[0]["tls_packet_count"] == 1
    assert rows[0]["dns_packet_count"] == 1
    assert rows[1]["packet_count"] == 2
    assert rows[1]["quic_packet_count"] == 1
    assert rows[1]["downlink_packet_count"] >= 1


def test_pcap_path_discovers_unregistered_pcapng(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = _scripted_manifest("run-pcapng", "bbc.mobile.news.ww")
    manifest["artifacts"] = []
    _write_json(run_dir / "run_manifest.json", manifest)
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    capture_dir.mkdir(parents=True)
    pcapng = capture_dir / "app_capture.pcapng"
    pcapng.write_bytes(b"pcapng")
    (capture_dir / "app_capture.pcapng.json").write_text("{}", encoding="utf-8")

    assert interaction_phases._pcap_path(run_dir) == pcapng
