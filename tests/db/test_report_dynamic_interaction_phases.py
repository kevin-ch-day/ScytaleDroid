from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_interaction_phases as report
from scytaledroid.DynamicAnalysis.pcap import interaction_phases


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_interaction_phases.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "interaction phases" in (proc.stdout or "").lower()


def test_generate_report_exports_phase_and_transport_rows(tmp_path: Path, monkeypatch) -> None:
    dynamic_root = tmp_path / "output" / "evidence" / "dynamic"
    run_dir = dynamic_root / "run-scripted"

    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run-scripted",
            "started_at": "2026-06-15T12:00:00Z",
            "target": {"package_name": "bbc.mobile.news.ww", "display_name": "BBC News"},
            "scenario": {"id": "paper3_profile_v3"},
            "operator": {
                "run_profile": "interaction_scripted",
                "interaction_level": "scripted",
                "template_id": "news_reader_basic_v1",
                "template_hash": "abc123",
                "template_map_version": "v1",
                "step_count_planned": 2,
            },
            "dataset": {
                "pcap_available": True,
                "valid_dataset_run": True,
                "invalid_reason_code": None,
            },
            "artifacts": [
                {
                    "relative_path": "artifacts/pcapdroid_capture/app.pcap",
                    "type": "pcapdroid_capture",
                    "produced_by": "pcapdroid_capture",
                }
            ],
        },
    )
    _write_jsonl(
        run_dir / "notes" / "run_events.jsonl",
        [
            {
                "timestamp": "2026-06-15T12:00:00Z",
                "event_type": "SCRIPT_START",
                "details": {
                    "template_id": "news_reader_basic_v1",
                    "template_hash": "abc123",
                    "template_map_version": "v1",
                    "step_count_planned": 2,
                },
            },
            {
                "timestamp": "2026-06-15T12:00:00Z",
                "event_type": "STEP_START",
                "details": {"step_id": "open_home", "step_index": 1, "expected_duration_s": 30},
            },
            {
                "timestamp": "2026-06-15T12:00:30Z",
                "event_type": "STEP_END",
                "details": {"step_id": "open_home", "step_index": 1, "expected_duration_s": 30, "elapsed_s": 30.0, "step_outcome": "completed"},
            },
            {
                "timestamp": "2026-06-15T12:00:30Z",
                "event_type": "STEP_START",
                "details": {"step_id": "scroll_headlines", "step_index": 2, "expected_duration_s": 50},
            },
            {
                "timestamp": "2026-06-15T12:01:20Z",
                "event_type": "STEP_END",
                "details": {"step_id": "scroll_headlines", "step_index": 2, "expected_duration_s": 50, "elapsed_s": 50.0, "step_outcome": "completed"},
            },
            {
                "timestamp": "2026-06-15T12:01:20Z",
                "event_type": "SCRIPT_END",
                "details": {
                    "template_id": "news_reader_basic_v1",
                    "template_hash": "abc123",
                    "template_map_version": "v1",
                    "step_count_planned": 2,
                    "step_count_completed": 2,
                },
            },
        ],
    )
    _write_json(
        run_dir / "analysis" / "interaction_timeline.json",
        {
            "schema_name": "scytaledroid.interaction_timeline",
            "schema_version": "1.1",
            "run_id": "run-scripted",
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
                    "step_id": "open_home",
                    "step_index": 1,
                    "step_variant": "",
                    "phase_label": "Open Home",
                    "planned_duration_sec": 30,
                    "actual_start_timestamp": "2026-06-15T12:00:00Z",
                    "actual_end_timestamp": "2026-06-15T12:00:30Z",
                    "actual_duration_sec": 30.0,
                    "operator_prompt": "Open the app and wait on the main/home feed.",
                    "operator_completed": True,
                    "step_outcome": "completed",
                    "limitation_reason": None,
                    "operator_note": None,
                    "notes": "",
                },
                {
                    "step_id": "scroll_headlines",
                    "step_index": 2,
                    "step_variant": "",
                    "phase_label": "Scroll Headlines",
                    "planned_duration_sec": 50,
                    "actual_start_timestamp": "2026-06-15T12:00:30Z",
                    "actual_end_timestamp": "2026-06-15T12:01:20Z",
                    "actual_duration_sec": 50.0,
                    "operator_prompt": "Slowly scroll the main headline/feed list.",
                    "operator_completed": True,
                    "step_outcome": "limited",
                    "limitation_reason": "paywall",
                    "operator_note": "subscription wall",
                    "notes": "",
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

    manual_run = dynamic_root / "run-manual"
    _write_json(
        manual_run / "run_manifest.json",
        {
            "dynamic_run_id": "run-manual",
            "target": {"package_name": "com.twitter.android", "display_name": "X"},
            "operator": {"run_profile": "interaction_manual", "interaction_level": "active"},
        },
    )

    monkeypatch.setattr(report, "_dynamic_root", lambda: dynamic_root)
    monkeypatch.setattr(
        interaction_phases,
        "extract_phase_packet_timeline",
        lambda _path: [
            interaction_phases.PhasePacketRecord(t=5.0, length=100, protocols="eth:ip:tcp:tls", src_port=50000, dst_port=443),
            interaction_phases.PhasePacketRecord(t=45.0, length=80, protocols="eth:ip:udp:dns", src_port=55555, dst_port=53),
        ],
    )

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["scripted_runs_seen"] == 1
    assert summary["timeline_complete_runs"] == 1
    assert summary["phase_rows_exported"] == 2
    assert summary["transport_rows_exported"] == 2
    assert summary["scripted_runs_valid_pcap"] == 1
    assert summary["scripted_runs_invalid_pcap"] == 0
    assert summary["scripted_runs_with_timeline_but_no_pcap"] == 0
    assert summary["transport_rows_skipped_missing_pcap"] == 0

    with (out_dir / "interaction_phase_summary.csv").open(encoding="utf-8") as handle:
        phase_rows = list(csv.DictReader(handle))
    assert len(phase_rows) == 2
    assert phase_rows[0]["package"] == "bbc.mobile.news.ww"
    assert phase_rows[0]["phase_label"] == "Open Home"
    assert phase_rows[1]["step_outcome"] == "limited"
    assert phase_rows[1]["limitation_reason"] == "paywall"
    assert phase_rows[1]["notes_present"] == "True"

    with (out_dir / "phase_packet_transport_summary.csv").open(encoding="utf-8") as handle:
        transport_rows = list(csv.DictReader(handle))
    assert len(transport_rows) == 2
    assert transport_rows[0]["packet_count"] == "1"
    assert transport_rows[1]["dns_packet_count"] == "1"
    assert transport_rows[1]["step_outcome"] == "limited"
    assert transport_rows[1]["limitation_reason"] == "paywall"


def test_generate_report_keeps_timeline_rows_when_pcap_missing(tmp_path: Path, monkeypatch) -> None:
    dynamic_root = tmp_path / "output" / "evidence" / "dynamic"
    run_dir = dynamic_root / "run-scripted-missing-pcap"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run-scripted-missing-pcap",
            "target": {"package_name": "com.cnn.mobile.android.phone", "display_name": "CNN"},
            "operator": {
                "run_profile": "interaction_scripted",
                "interaction_level": "scripted",
                "template_id": "news_reader_basic_v1",
                "template_hash": "cnn123",
                "template_map_version": "v1",
                "step_count_planned": 2,
            },
            "dataset": {
                "valid_dataset_run": False,
                "invalid_reason_code": "PCAP_MISSING",
                "pcap_available": False,
                "pcap_failure_detail": "PCAP_DEVICE_FILE_EMPTY",
                "timeline_available": True,
                "timeline_complete": True,
            },
        },
    )
    _write_json(
        run_dir / "analysis" / "interaction_timeline.json",
        {
            "run_id": "run-scripted-missing-pcap",
            "package": "com.cnn.mobile.android.phone",
            "run_profile": "interaction_scripted",
            "template_id": "news_reader_basic_v1",
            "template_hash": "cnn123",
            "planned_step_count": 2,
            "completed_step_count": 2,
            "timeline_complete": True,
            "steps": [
                {"step_id": "open_home", "step_index": 1, "phase_label": "Open Home", "planned_duration_sec": 30, "actual_duration_sec": 30.0, "operator_completed": True, "step_outcome": "completed", "limitation_reason": None, "notes": ""},
                {"step_id": "open_article", "step_index": 2, "phase_label": "Open Article", "planned_duration_sec": 45, "actual_duration_sec": 45.0, "operator_completed": True, "step_outcome": "completed", "limitation_reason": None, "notes": ""},
            ],
        },
    )
    monkeypatch.setattr(report, "_dynamic_root", lambda: dynamic_root)
    monkeypatch.setattr(interaction_phases, "phase_packet_transport_summary", lambda *_args, **_kwargs: [])

    out_dir = tmp_path / "audit-missing-pcap"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["scripted_runs_seen"] == 1
    assert summary["timeline_complete_runs"] == 1
    assert summary["phase_rows_exported"] == 2
    assert summary["transport_rows_exported"] == 0
    assert summary["scripted_runs_with_timeline_but_no_pcap"] == 1
    assert summary["scripted_runs_invalid_pcap"] == 1
    assert summary["scripted_runs_valid_pcap"] == 0
    assert summary["transport_rows_skipped_missing_pcap"] == 2

    with (out_dir / "interaction_phase_summary.csv").open(encoding="utf-8") as handle:
        phase_rows = list(csv.DictReader(handle))
    assert len(phase_rows) == 2

    with (out_dir / "phase_packet_transport_summary.csv").open(encoding="utf-8") as handle:
        transport_rows = list(csv.DictReader(handle))
    assert transport_rows == []


def test_main_prints_pcap_counters(capsys, monkeypatch, tmp_path: Path) -> None:
    summary_path = tmp_path / "summary.json"
    monkeypatch.setattr(
        report,
        "generate_report",
        lambda output_dir=None: {
            "scripted_runs_seen": 1,
            "timeline_complete_runs": 1,
            "timeline_incomplete_runs": 0,
            "phase_rows_exported": 6,
            "transport_rows_exported": 0,
            "scripted_runs_valid_pcap": 0,
            "scripted_runs_invalid_pcap": 1,
            "scripted_runs_with_timeline_but_no_pcap": 1,
            "transport_rows_skipped_missing_pcap": 6,
            "output_files": {"summary_json": str(summary_path)},
        },
    )

    rc = report.main([])

    out = capsys.readouterr().out
    assert rc == 0
    assert "scripted_runs_seen=1" in out
    assert "phase_rows_exported=6 transport_rows_exported=0" in out
    assert "scripted_runs_valid_pcap=0" in out
    assert "scripted_runs_invalid_pcap=1" in out
    assert "scripted_runs_with_timeline_but_no_pcap=1" in out
    assert "transport_rows_skipped_missing_pcap=6" in out
