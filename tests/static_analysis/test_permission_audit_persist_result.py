from __future__ import annotations

from scytaledroid.StaticAnalysis.modules.permissions.audit import PermissionAuditAccumulator
from scytaledroid.Utils.ops.operation_result import OperationResult


def test_permission_audit_persist_returns_failure_on_exception(monkeypatch):
    accumulator = PermissionAuditAccumulator(
        scope_label="Example app",
        scope_type="app",
        total_groups=1,
        snapshot_id="perm-audit:app:test-session",
    )

    def _raise(*_args, **_kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr(
        "scytaledroid.Database.db_func.permissions.permission_support.ensure_all",
        _raise,
    )

    result = accumulator.persist_to_db(
        {
            "session": "test-session",
            "scope_label": "Example app",
            "run_id": 10,
            "static_run_id": 20,
        }
    )

    assert isinstance(result, OperationResult)
    assert result.ok is False
    assert result.status == "FAILED"


def test_permission_audit_snapshot_artifact_pointer_nulls_inline_metadata(
    tmp_path, monkeypatch
):
    accumulator = PermissionAuditAccumulator(
        scope_label="Example app",
        scope_type="app",
        total_groups=0,
        snapshot_id="perm-audit:app:test-session",
    )
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_text('{"ok": true}', encoding="utf-8")
    queries: list[str] = []

    monkeypatch.setattr(
        "scytaledroid.Database.db_func.permissions.permission_support.ensure_all",
        lambda: None,
    )

    def _fake_run_sql(sql, params=(), **kwargs):  # noqa: ANN001, ANN202
        normalized = " ".join(str(sql).lower().split())
        queries.append(normalized)
        if "select snapshot_id from permission_audit_snapshots where snapshot_key" in normalized:
            return (42,)
        if "select static_run_id from permission_audit_snapshots where snapshot_id" in normalized:
            return (None,)
        return None

    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_queries.run_sql",
        _fake_run_sql,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.modules.permissions.audit.record_artifacts",
        lambda **_kwargs: None,
    )

    result = accumulator.persist_to_db(
        {
            "session": "test-session",
            "scope_label": "Example app",
            "paths": {"snapshot": str(snapshot_path)},
        }
    )

    assert result.ok is True
    assert any(
        "set evidence_relpath=%s, evidence_sha256=%s, metadata=null" in query
        for query in queries
    )
