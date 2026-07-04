from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.scenarios.manual_templates import template_steps_for_id


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def scripted_manifest(run_id: str, package: str) -> dict[str, object]:
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


def news_events(*, missing_step_end: bool = False) -> list[dict[str, object]]:
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
