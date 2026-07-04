from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap import interaction_phases
from tests.dynamic._interaction_phase_support import (
    news_events,
    scripted_manifest,
    write_json,
    write_jsonl,
)


def test_interaction_phases_end_to_end_timeline_and_rows(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    manifest = scripted_manifest("run-1", "bbc.mobile.news.ww")
    write_json(run_dir / "run_manifest.json", manifest)
    write_jsonl(run_dir / "notes" / "run_events.jsonl", news_events())

    timeline = interaction_phases.build_interaction_timeline_from_run_dir(run_dir)
    assert timeline is not None

    rows = interaction_phases.build_protocol_phase_marker_rows(timeline)
    assert timeline["timeline_complete"] is True
    assert len(rows) == timeline["completed_step_count"]
    assert rows[0]["marker_type"] == "step_window"
    assert rows[0]["phase_id"] == "open_home"
