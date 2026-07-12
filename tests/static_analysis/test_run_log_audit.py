from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.StaticAnalysis.audit.run_log_audit import (
    persistence_audit_candidates,
    scan_log_tail,
    summarize_persistence_audit,
    static_session_log_candidates,
    tail_text_lines,
)
from scytaledroid.Utils.LoggingUtils import logging_context
from scytaledroid.Utils.LoggingUtils import logging_engine


def test_tail_text_lines_returns_suffix(tmp_path: Path) -> None:
    path = tmp_path / "sample.log"
    lines = "\n".join(f"line-{idx}" for idx in range(5))
    path.write_text(lines + "\n", encoding="utf-8")

    tail = tail_text_lines(path, max_lines=3)
    assert tail == ["line-2", "line-3", "line-4"]


def test_scan_log_tail_matches_session(tmp_path: Path) -> None:
    path = tmp_path / "static.log"
    path.write_text("noise\nstamp 20260101-unit-test-session ok\nnoise\n", encoding="utf-8")

    hits = scan_log_tail(
        path,
        session="20260101-unit-test-session",
        tail_lines=100,
        markers=("zzznomatchmarker",),
        extras=(),
        max_report=10,
    )
    assert len(hits) == 1
    assert "20260101-unit-test-session" in hits[0]


def test_persistence_audit_candidates(tmp_path: Path) -> None:
    a, b = persistence_audit_candidates("sess-x", output_root=tmp_path)
    assert a == tmp_path / "audit" / "persistence" / "sess-x_persistence_audit.json"
    assert b == tmp_path / "audit" / "persistence" / "sess-x_missing_run_ids.json"


def test_static_session_log_candidates_returns_latest_pair(tmp_path: Path) -> None:
    static_dir = tmp_path / "static"
    static_dir.mkdir(parents=True)
    older_text = static_dir / "20260628T010000Z_session-20260628-all-full.log"
    older_json = static_dir / "20260628T010000Z_session-20260628-all-full.jsonl"
    newer_text = static_dir / "20260628T020000Z_session-20260628-all-full.log"
    newer_json = static_dir / "20260628T020000Z_session-20260628-all-full.jsonl"
    for path in (older_text, older_json, newer_text, newer_json):
        path.write_text("", encoding="utf-8")

    text_path, json_path = static_session_log_candidates(
        "20260628-all-full",
        logs_root=tmp_path,
    )

    assert text_path == newer_text
    assert json_path == newer_json


def test_summarize_persistence_audit_prints_outcome(
    tmp_path: Path, capsys,
) -> None:
    audit = tmp_path / "audit.json"
    audit.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "total_apps": 2,
                "summary": {
                    "outcome": {
                        "canonical_failed": False,
                        "persistence_failed": True,
                        "compat_export_failed": False,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    summarize_persistence_audit(audit)
    out = capsys.readouterr().out
    assert "persistence_failed=True" in out
    assert "schema_version" in out


def test_static_session_logger_writes_dedicated_files_and_run_context(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(logging_engine, "LOG_DIR", tmp_path)

    logging_engine.create_static_session_logger(
        "20260628-all-full",
        context={"subsystem": "static", "scope_label": "All harvested apps"},
    )
    try:
        run_ctx = logging_context.RunContext(
            subsystem="static",
            device_serial="ZY22JK89DR",
            device_model="moto g 5G - 2024",
            run_id="20260628-all-full",
            scope="All apps",
            profile="Full",
        )
        logger = logging_context.get_run_logger("static", run_ctx)
        logger.info("Static test event", extra={"event": "unit.test"})
    finally:
        logging_engine.close_static_session_logger("20260628-all-full")

    static_dir = tmp_path / "static"
    text_logs = sorted(static_dir.glob("*_session-20260628-all-full.log"))
    json_logs = sorted(static_dir.glob("*_session-20260628-all-full.jsonl"))

    assert len(text_logs) == 1
    assert len(json_logs) == 1
    assert "Static test event" in text_logs[0].read_text(encoding="utf-8")
    assert '"event": "unit.test"' in json_logs[0].read_text(encoding="utf-8")


def test_static_session_logger_mirrors_shared_static_logger_events(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(logging_engine, "LOG_DIR", tmp_path)

    logging_engine.create_static_session_logger("20260628-all-full")
    try:
        logging_engine.get_static_logger().info(
            "Shared static event",
            extra=logging_engine.ensure_trace(
                {
                    "event": "shared.unit.test",
                    "session_stamp": "20260628-all-full",
                    "run_id": "20260628-all-full",
                }
            ),
        )
    finally:
        logging_engine.close_static_session_logger("20260628-all-full")

    json_logs = sorted((tmp_path / "static").glob("*_session-20260628-all-full.jsonl"))
    assert len(json_logs) == 1
    text = json_logs[0].read_text(encoding="utf-8")
    assert '"event": "shared.unit.test"' in text
    assert "Shared static event" in text
