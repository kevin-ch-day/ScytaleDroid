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
