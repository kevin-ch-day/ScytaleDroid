from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap import interaction_phases
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
