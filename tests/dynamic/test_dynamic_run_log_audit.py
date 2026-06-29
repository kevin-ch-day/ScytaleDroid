from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.audit.run_log_audit import (
    dynamic_run_log_candidates,
    summarize_dynamic_run_artifacts,
)


def test_dynamic_run_log_candidates_returns_latest_pair(tmp_path: Path) -> None:
    dynamic_dir = tmp_path / "dynamic"
    dynamic_dir.mkdir(parents=True)
    older_text = dynamic_dir / "20260628T010000Z_run-run-123.log"
    older_json = dynamic_dir / "20260628T010000Z_run-run-123.jsonl"
    newer_text = dynamic_dir / "20260628T020000Z_run-run-123.log"
    newer_json = dynamic_dir / "20260628T020000Z_run-run-123.jsonl"
    for path in (older_text, older_json, newer_text, newer_json):
        path.write_text("", encoding="utf-8")

    text_path, json_path = dynamic_run_log_candidates("run-123", logs_root=tmp_path)

    assert text_path == newer_text
    assert json_path == newer_json


def test_summarize_dynamic_run_artifacts_reports_core_paths(tmp_path: Path) -> None:
    logs_root = tmp_path / "logs"
    evidence_root = tmp_path / "output" / "evidence" / "dynamic"
    run_id = "run-123"
    run_dir = evidence_root / run_id
    (logs_root / "dynamic").mkdir(parents=True)
    (run_dir / "notes").mkdir(parents=True)
    (run_dir / "analysis" / "index" / "v1").mkdir(parents=True)

    (logs_root / "dynamic" / "20260628T020000Z_run-run-123.log").write_text("ok", encoding="utf-8")
    (logs_root / "dynamic" / "20260628T020000Z_run-run-123.jsonl").write_text("{}", encoding="utf-8")
    (run_dir / "notes" / "run_events.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"event_type": "dataset_validity", "details": {"valid": True, "countable": True}}),
                json.dumps(
                    {
                        "event_type": "dynamic_derived_indexing_complete",
                        "details": {"feature_rows": 1, "indicator_rows": 20, "domain_rows": 20},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "notes" / "run_monitor.jsonl").write_text("{}", encoding="utf-8")
    (run_dir / "analysis" / "pcap_report.json").write_text("{}", encoding="utf-8")
    (run_dir / "analysis" / "pcap_features.json").write_text("{}", encoding="utf-8")
    (run_dir / "analysis" / "static_dynamic_overlap.json").write_text("{}", encoding="utf-8")
    (run_dir / "analysis" / "index" / "v1" / "db_persistence_status.json").write_text(
        json.dumps({"attempted": True, "ok": True}),
        encoding="utf-8",
    )

    summary = summarize_dynamic_run_artifacts(
        run_id,
        logs_root=logs_root,
        evidence_root=evidence_root,
    )

    assert summary["run_dir_exists"] is True
    assert summary["events_present"] is True
    assert summary["event_count"] == 2
    assert summary["monitor_present"] is True
    assert summary["pcap_report_present"] is True
    assert summary["pcap_features_present"] is True
    assert summary["overlap_present"] is True
    assert summary["db_persistence_status"] == {"attempted": True, "ok": True}
    assert summary["latest_dataset_validity"] == {"valid": True, "countable": True}
    assert summary["latest_derived_indexing"] == {"feature_rows": 1, "indicator_rows": 20, "domain_rows": 20}
