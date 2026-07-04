from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.pcap import interaction_phases
from tests.dynamic._interaction_phase_support import scripted_manifest, write_json


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
    manifest = scripted_manifest("run-fb", "com.facebook.katana")
    write_json(run_dir / "run_manifest.json", manifest)
    write_json(
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


def test_phase_packet_transport_summary_slices_packets_by_step(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run"
    manifest = scripted_manifest("run-4", "bbc.mobile.news.ww")
    write_json(run_dir / "run_manifest.json", manifest)
    write_json(
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
    write_json(
        run_dir / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json",
        {"capture_start_epoch": 1781524800.0},
    )
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "pcapdroid_capture" / "app.pcap").write_bytes(b"pcap")

    monkeypatch.setattr(
        interaction_phases,
        "extract_phase_packet_timeline",
        lambda _path: [
            interaction_phases.PhasePacketRecord(
                t=5.0, length=100, protocols="eth:ip:tcp:tls", src_port=50000, dst_port=443
            ),
            interaction_phases.PhasePacketRecord(
                t=10.0, length=80, protocols="eth:ip:udp:dns", src_port=55555, dst_port=53
            ),
            interaction_phases.PhasePacketRecord(
                t=12.0,
                length=90,
                protocols="eth:ip:tcp:http",
                src_port=50000,
                dst_port=80,
                http_host="Tracker.Example",
            ),
            interaction_phases.PhasePacketRecord(
                t=40.0, length=120, protocols="eth:ip:udp:quic", src_port=50000, dst_port=443
            ),
            interaction_phases.PhasePacketRecord(
                t=70.0, length=90, protocols="eth:ip:tcp:tls", src_port=443, dst_port=50000
            ),
        ],
    )

    rows = interaction_phases.phase_packet_transport_summary(run_dir)

    assert len(rows) == 2
    assert rows[0]["packet_count"] == 3
    assert rows[0]["tls_packet_count"] == 1
    assert rows[0]["dns_packet_count"] == 1
    assert rows[0]["http_packet_count"] == 1
    assert rows[0]["cleartext_surface_flag"] == 1
    assert rows[0]["http_host_count"] == 1
    assert rows[0]["http_hosts_sample"] == "tracker.example"
    assert rows[1]["packet_count"] == 2
    assert rows[1]["quic_packet_count"] == 1
    assert rows[1]["downlink_packet_count"] >= 1


def test_pcap_path_discovers_unregistered_pcapng(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = scripted_manifest("run-pcapng", "bbc.mobile.news.ww")
    manifest["artifacts"] = []
    write_json(run_dir / "run_manifest.json", manifest)
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    capture_dir.mkdir(parents=True)
    pcapng = capture_dir / "app_capture.pcapng"
    pcapng.write_bytes(b"pcapng")
    (capture_dir / "app_capture.pcapng.json").write_text("{}", encoding="utf-8")

    assert interaction_phases._pcap_path(run_dir) == pcapng
