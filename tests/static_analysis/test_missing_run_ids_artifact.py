from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch


def _stub_lock_snapshot(monkeypatch) -> None:
    monkeypatch.setattr(
        run_dispatch.db_diagnostics,
        "get_lock_health_snapshot",
        lambda limit=25: {"schema_version": "v1", "active_process_count": 0, "limit": limit},
    )


def _stub_audit_summary_queries(monkeypatch) -> None:
    from scytaledroid.Database.db_core import db_queries as core_q

    def _fake_run_sql(query, params=(), fetch="none", **_kwargs):
        sql = " ".join(str(query).split())
        if "SELECT status, COUNT(*) FROM static_analysis_runs" in sql:
            return [("COMPLETED", 1)]
        if "COUNT(*) FROM static_analysis_runs WHERE session_label=%s AND is_canonical=1" in sql:
            return (1,)
        if "COUNT(*) FROM static_analysis_runs WHERE session_label=%s AND static_handoff_json_path IS NOT NULL" in sql:
            return (1,)
        if "COUNT(*) FROM static_analysis_findings" in sql:
            return (5,)
        if "COUNT(*) FROM static_permission_matrix" in sql:
            return (7,)
        if "COUNT(*) FROM static_permission_risk_vnext" in sql:
            return (7,)
        if "SELECT package_name FROM static_findings_summary" in sql:
            return [("com.ok",)]
        if "SELECT package_name FROM static_string_summary" in sql:
            return [("com.ok",)]
        if "SELECT package FROM runs" in sql and "session_stamp=%s" in sql:
            return [("com.ok",)]
        if "SELECT package_name FROM risk_scores" in sql:
            return [("com.ok",)]
        if "SELECT DISTINCT lr.package FROM findings" in sql:
            return [("com.ok",)]
        if "SELECT DISTINCT lr.package FROM metrics" in sql:
            return [("com.ok",)]
        if "SELECT DISTINCT lr.package FROM buckets" in sql:
            return [("com.ok",)]
        if "SELECT DISTINCT lr.package FROM contributors" in sql:
            return [("com.ok",)]
        if "COUNT(*) FROM static_session_run_links" in sql:
            return (1,)
        if "COUNT(*) FROM static_session_rollups" in sql:
            return (0,)
        raise AssertionError(f"Unexpected query: {query}")

    monkeypatch.setattr(core_q, "run_sql", _fake_run_sql)


def test_emit_missing_run_ids_artifact(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_lock_snapshot(monkeypatch)
    _stub_audit_summary_queries(monkeypatch)
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
    assert payload["artifact_kind"] == "missing_run_ids"
    assert payload["schema_version"] == "v2"
    assert payload["db_schema_version"]
    assert payload["generated_at_utc"]
    assert payload["missing_static_run_id_count"] == 1
    assert payload["summary"]["expected_packages"] == 2
    rows = {row["package_name"]: row for row in payload["rows"]}
    assert rows["com.ok"]["missing_static_run_id"] is False
    assert rows["com.missing"]["missing_static_run_id"] is True
    lock_path = tmp_path / "output" / "audit" / "persistence" / "20260216_db_lock_health.json"
    lock_payload = json.loads(lock_path.read_text(encoding="utf-8"))
    assert lock_payload["active_process_count"] == 0


def test_emit_missing_run_ids_artifact_uses_neutral_name_when_no_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_lock_snapshot(monkeypatch)
    _stub_audit_summary_queries(monkeypatch)
    results = [AppRunResult(package_name="com.ok", category="Test", static_run_id=12)]
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
        linkage_blocked_reason=None,
        missing_id_packages=[],
    )

    out = tmp_path / "output" / "audit" / "persistence" / "20260216_persistence_audit.json"
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["artifact_kind"] == "persistence_audit"
    assert payload["missing_static_run_id_count"] == 0
    assert payload["summary"]["canonical"]["run_statuses"] == {"COMPLETED": 1}
    assert not (tmp_path / "output" / "audit" / "persistence" / "20260216_missing_run_ids.json").exists()


def test_emit_missing_run_ids_artifact_extracts_retry_and_disconnect(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_lock_snapshot(monkeypatch)
    _stub_audit_summary_queries(monkeypatch)
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
    assert payload["artifact_kind"] == "missing_run_ids"
    rows = {row["package_name"]: row for row in payload["rows"]}
    missing = rows["com.missing"]
    assert missing["missing_static_run_id"] is True
    assert missing["classification"] == "db_write_failed"
    assert missing["stage"] == "permission_risk.write"
    assert missing["db_disconnect"] is True
    assert missing["retry_count"] == 2


def test_emit_missing_run_ids_artifact_prefers_structured_persistence_fields(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_lock_snapshot(monkeypatch)
    _stub_audit_summary_queries(monkeypatch)
    result = AppRunResult(package_name="com.missing", category="Test", static_run_id=None)
    result.persistence_retry_count = 3
    result.persistence_db_disconnect = True
    result.persistence_transaction_state = "rolled_back"
    result.persistence_exception_class = "TransientDbError"
    result.persistence_failure_stage = "permission_risk.write"

    scope = ScopeSelection(scope="all", label="All apps", groups=tuple())
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[result],
        started_at=now,
        finished_at=now,
        scope=scope,
        base_dir=tmp_path,
        failures=["com.missing generic failure message without retry markers"],
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
    assert missing["retry_count"] == 3
    assert missing["db_disconnect"] is True
    assert missing["transaction_state"] == "rolled_back"
    assert missing["exception_class"] == "TransientDbError"
    assert missing["stage"] == "permission_risk.write"


def test_emit_missing_run_ids_artifact_classifies_lock_wait_timeout(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_lock_snapshot(monkeypatch)
    _stub_audit_summary_queries(monkeypatch)
    result = AppRunResult(package_name="com.lockwait", category="Test", static_run_id=None)
    result.persistence_retry_count = 1
    result.persistence_db_disconnect = False
    result.persistence_transaction_state = "rolled_back"
    result.persistence_exception_class = "RuntimeError"
    result.persistence_failure_stage = "buckets.write"

    scope = ScopeSelection(scope="all", label="All apps", groups=tuple())
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[result],
        started_at=now,
        finished_at=now,
        scope=scope,
        base_dir=tmp_path,
        failures=[
            "Static persistence transaction failed for com.lockwait: "
            "buckets.write:TransientDbError:(1205, 'Lock wait timeout exceeded; try restarting transaction') "
            "(retry_count=1 transaction_state=rolled_back stage=buckets.write db_disconnect=0)"
        ],
    )

    run_dispatch._emit_missing_run_ids_artifact(  # noqa: SLF001 - contract guard
        outcome=outcome,
        session_stamp="20260216",
        linkage_blocked_reason="static_run_id missing for one or more apps",
        missing_id_packages=["com.lockwait"],
    )

    out = tmp_path / "output" / "audit" / "persistence" / "20260216_missing_run_ids.json"
    payload = json.loads(out.read_text(encoding="utf-8"))
    rows = {row["package_name"]: row for row in payload["rows"]}
    missing = rows["com.lockwait"]
    assert missing["classification"] == "db_lock_wait"
    assert missing["db_lock_wait"] is True
    assert missing["errno"] == 1205


def test_emit_missing_run_ids_artifact_records_report_storage_and_completed_stage(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_lock_snapshot(monkeypatch)
    _stub_audit_summary_queries(monkeypatch)
    result = AppRunResult(package_name="com.ok", category="Test", static_run_id=12)
    now = datetime.now(UTC)
    from scytaledroid.StaticAnalysis.cli.core.models import ArtifactOutcome

    result.artifacts = [
        ArtifactOutcome(
            label="base",
            report=object(),  # type: ignore[arg-type]
            severity={},
            duration_seconds=1.0,
            saved_path="data/static_analysis/reports/latest/example.json",
            started_at=now,
            finished_at=now,
            metadata=None,
        )
    ]
    monkeypatch.setattr(AppRunResult, "base_artifact_outcome", lambda self: self.artifacts[0])
    result.persistence_transaction_state = "committed"
    outcome = RunOutcome(
        results=[result],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=tmp_path,
    )

    run_dispatch._emit_missing_run_ids_artifact(  # noqa: SLF001 - contract guard
        outcome=outcome,
        session_stamp="20260216",
        linkage_blocked_reason=None,
        missing_id_packages=[],
    )

    payload = json.loads(
        (tmp_path / "output" / "audit" / "persistence" / "20260216_persistence_audit.json").read_text(
            encoding="utf-8"
        )
    )
    row = payload["rows"][0]
    assert row["stage"] == "completed"
    assert row["artifact_reports"] == 1
    assert row["report_storage_mode"] == "latest"
    assert row["base_report_path"].endswith("example.json")
