from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.session import DynamicSessionConfig, DynamicSessionResult
from scytaledroid.DynamicAnalysis.storage import persistence


def _make_result(tmp_path: Path, status: str) -> DynamicSessionResult:
    return DynamicSessionResult(
        package_name="com.example.app",
        duration_seconds=30,
        started_at=datetime.now(UTC),
        ended_at=datetime.now(UTC),
        status=status,
        notes="test",
        dynamic_run_id="run-123",
        evidence_path=str(tmp_path),
    )


def test_persist_dynamic_summary_inserts_plan_validation_issue(monkeypatch, tmp_path):
    monkeypatch.setattr(persistence.dynamic_schema, "ensure_all", lambda: True)
    captured = {"writes": [], "many": []}

    monkeypatch.setattr(
        persistence.core_q,
        "run_sql_write",
        lambda *args, **kwargs: captured["writes"].append((args, kwargs)),
    )
    monkeypatch.setattr(
        persistence.core_q,
        "run_sql_many",
        lambda *args, **kwargs: captured["many"].append((args, kwargs)),
    )

    result = _make_result(tmp_path, "blocked")
    payload = {
        "dynamic_run_id": "run-123",
        "plan_validation": {"validation_result": "FAIL", "reasons": ["missing required fields"]},
        "plan": {"package": "com.example.app", "static_run_id": 1, "run_signature_version": "v0"},
    }
    config = DynamicSessionConfig(package_name="com.example.app", duration_seconds=30)

    persistence.persist_dynamic_summary(config, result, payload)

    assert captured["writes"]
    assert captured["many"]
    issue_call = next(
        (
            entry
            for entry in captured["many"]
            if "dynamic_session_issues" in str(entry[0][0])
        ),
        None,
    )
    assert issue_call is not None
    inserted = issue_call[0][1]
    assert any(row[1] == "plan_validation_fail" for row in inserted)


def test_persist_dynamic_summary_extracts_observer_issues(monkeypatch, tmp_path):
    monkeypatch.setattr(persistence.dynamic_schema, "ensure_all", lambda: True)
    captured = {"writes": [], "many": []}

    monkeypatch.setattr(
        persistence.core_q,
        "run_sql_write",
        lambda *args, **kwargs: captured["writes"].append((args, kwargs)),
    )
    monkeypatch.setattr(
        persistence.core_q,
        "run_sql_many",
        lambda *args, **kwargs: captured["many"].append((args, kwargs)),
    )

    manifest = {
        "observers": [
            {"observer_id": "proxy_capture", "status": "failed", "error": "boom"},
            {
                "observer_id": "network_capture",
                "status": "skipped",
                "error": "tcpdump not available on device (non-root)",
            },
        ]
    }
    (tmp_path / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    result = _make_result(tmp_path, "degraded")
    payload = {"dynamic_run_id": "run-123", "plan": {}}
    config = DynamicSessionConfig(package_name="com.example.app", duration_seconds=30)

    persistence.persist_dynamic_summary(config, result, payload)

    assert captured["many"]
    issue_call = next(
        (
            entry
            for entry in captured["many"]
            if "dynamic_session_issues" in str(entry[0][0])
        ),
        None,
    )
    assert issue_call is not None
    inserted = issue_call[0][1]
    codes = {row[1] for row in inserted}
    assert "proxy_capture_failed" in codes
    assert "tcpdump_unavailable_nonroot" in codes
