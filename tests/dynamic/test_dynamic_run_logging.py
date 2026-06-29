from __future__ import annotations

from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig
from scytaledroid.DynamicAnalysis.engine import DynamicAnalysisEngine
from scytaledroid.DynamicAnalysis.plans.loader import PlanValidationOutcome
from scytaledroid.Utils.LoggingUtils import logging_engine


def test_dynamic_run_logger_mirrors_shared_dynamic_logger_events(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(logging_engine, "LOG_DIR", tmp_path)

    logging_engine.create_dynamic_run_logger(
        "run-123",
        context={"subsystem": "dynamic", "package_name": "com.example.app"},
    )
    try:
        logging_engine.get_dynamic_logger().info(
            "Shared dynamic event",
            extra=logging_engine.ensure_trace(
                {
                    "event": "dynamic.unit.test",
                    "dynamic_run_id": "run-123",
                    "run_id": "run-123",
                    "package_name": "com.example.app",
                }
            ),
        )
    finally:
        logging_engine.close_dynamic_run_logger("run-123")

    dynamic_dir = tmp_path / "dynamic"
    text_logs = sorted(dynamic_dir.glob("*_run-run-123.log"))
    json_logs = sorted(dynamic_dir.glob("*_run-run-123.jsonl"))

    assert len(text_logs) == 1
    assert len(json_logs) == 1
    assert "Shared dynamic event" in text_logs[0].read_text(encoding="utf-8")
    json_text = json_logs[0].read_text(encoding="utf-8")
    assert '"event": "dynamic.unit.test"' in json_text
    assert '"dynamic_run_id": "run-123"' in json_text


def test_blocked_dynamic_run_writes_dedicated_dynamic_log(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(logging_engine, "LOG_DIR", tmp_path / "logs")

    config = DynamicSessionConfig(
        package_name="com.example.app",
        duration_seconds=30,
        device_serial="ZY22JK89DR",
        tier="dataset",
        scenario_id="basic_usage",
        output_root=str(tmp_path / "output" / "evidence" / "dynamic"),
    )
    engine = DynamicAnalysisEngine(config)
    outcome = PlanValidationOutcome(
        status="FAIL",
        reasons=["missing required fields: static_handoff_hash"],
        warnings=[],
        mismatches=[],
        plan={"package": "com.example.app", "static_run_id": 1},
        db={},
    )

    run_id, _run_dir = engine._write_blocked_event(outcome)

    dynamic_dir = (tmp_path / "logs" / "dynamic")
    text_logs = sorted(dynamic_dir.glob(f"*_run-{run_id}.log"))
    json_logs = sorted(dynamic_dir.glob(f"*_run-{run_id}.jsonl"))

    assert len(text_logs) == 1
    assert len(json_logs) == 1
    assert "Dynamic plan validation blocked run" in text_logs[0].read_text(encoding="utf-8")
    json_text = json_logs[0].read_text(encoding="utf-8")
    assert '"validation_result": "FAIL"' in json_text
    assert '"dynamic_run_id"' in json_text
