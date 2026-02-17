from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch


def test_emit_missing_run_ids_artifact(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    results = [
        AppRunResult(package_name="com.ok", category="Test", static_run_id=12),
        AppRunResult(package_name="com.missing", category="Test", static_run_id=None),
    ]
    scope = ScopeSelection(scope="all", label="All apps", groups=tuple())
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=results,
        started_at=now,
        finished_at=now,
        scope=scope,
        base_dir=tmp_path,
    )

    run_dispatch._emit_missing_run_ids_artifact(  # noqa: SLF001 - contract guard
        outcome=outcome,
        session_stamp="20260216",
        linkage_blocked_reason="static_run_id missing for one or more apps",
        missing_id_packages=["com.missing"],
    )

    out = tmp_path / "output" / "audit" / "persistence" / "20260216_missing_run_ids.json"
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "v1"
    assert payload["db_schema_version"]
    assert payload["generated_at_utc"]
    assert payload["missing_static_run_id_count"] == 1
    rows = {row["package_name"]: row for row in payload["rows"]}
    assert rows["com.ok"]["missing_static_run_id"] is False
    assert rows["com.missing"]["missing_static_run_id"] is True


def test_emit_missing_run_ids_artifact_extracts_retry_and_disconnect(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    results = [AppRunResult(package_name="com.missing", category="Test", static_run_id=None)]
    scope = ScopeSelection(scope="all", label="All apps", groups=tuple())
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=results,
        started_at=now,
        finished_at=now,
        scope=scope,
        base_dir=tmp_path,
        failures=[
            "com.missing db_write_failed:permission_risk.write:TransientDbError:(2013) retry_count=2"
        ],
    )

    run_dispatch._emit_missing_run_ids_artifact(  # noqa: SLF001 - contract guard
        outcome=outcome,
        session_stamp="20260216",
        linkage_blocked_reason="static_run_id missing for one or more apps",
        missing_id_packages=["com.missing"],
    )

    out = tmp_path / "output" / "audit" / "persistence" / "20260216_missing_run_ids.json"
    payload = json.loads(out.read_text(encoding="utf-8"))
    rows = {row["package_name"]: row for row in payload["rows"]}
    missing = rows["com.missing"]
    assert missing["missing_static_run_id"] is True
    assert missing["classification"] == "db_write_failed"
    assert missing["stage"] == "permission_risk.write"
    assert missing["db_disconnect"] is True
    assert missing["retry_count"] == 2
