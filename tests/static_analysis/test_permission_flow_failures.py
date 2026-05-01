from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.execution import permission_flow
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact
from scytaledroid.Utils.ops.operation_result import OperationResult


@dataclass
class _FakeManifest:
    package_name: str = "com.example.app"
    app_label: str = "Example"
    version_code: int = 100
    version_name: str = "1.0"
    target_sdk: int = 35
    min_sdk: int = 23


@dataclass
class _FakeReport:
    manifest: _FakeManifest


def _make_selection(tmp_path: Path) -> ScopeSelection:
    artifact_path = tmp_path / "com.example.app__base.apk"
    artifact_path.write_text("stub", encoding="utf-8")
    artifact = RepositoryArtifact(
        path=artifact_path,
        display_path=str(artifact_path),
        metadata={"package_name": "com.example.app", "version_name": "1.0"},
    )
    group = ArtifactGroup(
        group_key="com.example.app",
        package_name="com.example.app",
        version_display="1.0",
        session_stamp="20260123-000000",
        capture_id="20260123-000000",
        artifacts=(artifact,),
    )
    return ScopeSelection(scope="app", label="Example app", groups=(group,))


def test_permission_flow_marks_failed_on_persist_failure(tmp_path, monkeypatch, capsys):
    selection = _make_selection(tmp_path)
    params = RunParameters(profile="permissions", scope="app", scope_label="Example app")

    def _fake_generate_report(_artifact, _base_dir, _params):
        return _FakeReport(manifest=_FakeManifest()), None, None, False

    def _fake_collect_permissions_and_sdk(_path):
        return [("android.permission.CAMERA", "framework")], {}, {"target_sdk": 35}

    def _fake_render_permission_profile(*_args, **_kwargs):
        return {"risk_counts": {"dangerous": 1, "signature": 0}, "V": 0, "score_detail": {"score_raw": 1}}

    def _fake_persist_to_db(_payload):
        return OperationResult.failure(user_message="Permission audit persistence failed.")

    updates = []

    def _fake_finalize_static_run(*, static_run_id, status, **_kwargs):
        updates.append((static_run_id, status))

    monkeypatch.setattr(permission_flow, "generate_report", _fake_generate_report)
    monkeypatch.setattr(permission_flow, "collect_permissions_and_sdk", _fake_collect_permissions_and_sdk)
    monkeypatch.setattr(permission_flow, "render_permission_profile", _fake_render_permission_profile)
    monkeypatch.setattr(permission_flow.PermissionAuditAccumulator, "persist_to_db", _fake_persist_to_db)
    monkeypatch.setattr(permission_flow, "finalize_static_run", _fake_finalize_static_run)

    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_queries.run_sql",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        permission_flow,
        "create_static_run_ledger",
        lambda **_kwargs: 202,
    )

    permission_flow.execute_permission_scan(selection, params, persist_detections=True)

    stdout = capsys.readouterr().out
    assert "Persistence failed" in stdout
    assert updates and updates[-1][1] == "FAILED"


def test_permission_flow_raises_when_fail_on_persist_error_enabled(tmp_path, monkeypatch):
    selection = _make_selection(tmp_path)
    params = RunParameters(profile="permissions", scope="app", scope_label="Example app")

    def _fake_generate_report(_artifact, _base_dir, _params):
        return _FakeReport(manifest=_FakeManifest()), None, None, False

    def _fake_collect_permissions_and_sdk(_path):
        return [("android.permission.CAMERA", "framework")], {}, {"target_sdk": 35}

    def _fake_render_permission_profile(*_args, **_kwargs):
        return {"risk_counts": {"dangerous": 1, "signature": 0}, "V": 0, "score_detail": {"score_raw": 1}}

    def _fake_persist_to_db(_payload):
        return OperationResult.failure(
            user_message="Permission audit persistence failed.",
            error_code="perm_audit_snapshot_insert_failed",
        )

    monkeypatch.setattr(permission_flow, "generate_report", _fake_generate_report)
    monkeypatch.setattr(permission_flow, "collect_permissions_and_sdk", _fake_collect_permissions_and_sdk)
    monkeypatch.setattr(permission_flow, "render_permission_profile", _fake_render_permission_profile)
    monkeypatch.setattr(permission_flow.PermissionAuditAccumulator, "persist_to_db", _fake_persist_to_db)
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_queries.run_sql",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        permission_flow,
        "create_static_run_ledger",
        lambda **_kwargs: 202,
    )

    import pytest

    with pytest.raises(RuntimeError, match="Permission audit persistence failed"):
        permission_flow.execute_permission_scan(
            selection,
            params,
            persist_detections=True,
            fail_on_persist_error=True,
        )


def test_permission_flow_does_not_create_legacy_run_for_permission_only_scan(tmp_path, monkeypatch):
    selection = _make_selection(tmp_path)
    params = RunParameters(profile="permissions", scope="app", scope_label="Example app")
    captured: dict[str, object] = {}

    def _fake_generate_report(_artifact, _base_dir, _params):
        return _FakeReport(manifest=_FakeManifest()), None, None, False

    def _fake_collect_permissions_and_sdk(_path):
        return [("android.permission.CAMERA", "framework")], {}, {"target_sdk": 35}

    def _fake_render_permission_profile(*_args, **_kwargs):
        return {"risk_counts": {"dangerous": 1, "signature": 0}, "V": 0, "score_detail": {"score_raw": 1}}

    def _fake_persist_to_db(_self, payload):
        captured["payload"] = payload
        return OperationResult.success()

    def _unexpected_create_run(**_kwargs):
        raise AssertionError("legacy create_run should not be called for permission-only scans")

    monkeypatch.setattr(permission_flow, "generate_report", _fake_generate_report)
    monkeypatch.setattr(permission_flow, "collect_permissions_and_sdk", _fake_collect_permissions_and_sdk)
    monkeypatch.setattr(permission_flow, "render_permission_profile", _fake_render_permission_profile)
    monkeypatch.setattr(permission_flow.PermissionAuditAccumulator, "persist_to_db", _fake_persist_to_db)
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.persistence.permissions_db.persist_permissions_to_db",
        lambda *_a, **_k: {"aosp": 1, "oem": 0, "app_defined": 0, "unknown": 0},
    )
    monkeypatch.setattr("scytaledroid.Persistence.db_writer.create_run", _unexpected_create_run)
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_queries.run_sql",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        permission_flow,
        "create_static_run_ledger",
        lambda **_kwargs: 202,
    )
    monkeypatch.setattr(permission_flow, "finalize_static_run", lambda **_kwargs: None)

    permission_flow.execute_permission_scan(selection, params, persist_detections=True)

    assert captured["payload"]["run_id"] is None
    assert captured["payload"]["static_run_id"] == 202


def test_permission_flow_retries_when_snapshot_header_has_no_app_rows(tmp_path, monkeypatch):
    selection = _make_selection(tmp_path)
    params = RunParameters(profile="permissions", scope="app", scope_label="Example app")

    def _fake_generate_report(_artifact, _base_dir, _params):
        return _FakeReport(manifest=_FakeManifest()), None, None, False

    def _fake_collect_permissions_and_sdk(_path):
        return [("android.permission.CAMERA", "framework")], {}, {"target_sdk": 35}

    def _fake_render_permission_profile(*_args, **_kwargs):
        return {"risk_counts": {"dangerous": 1, "signature": 0}, "V": 0, "score_detail": {"score_raw": 1}}

    calls = {"persist": 0}

    def _fake_persist_to_db(_payload):
        calls["persist"] += 1
        return OperationResult.success()

    def _fake_run_sql(sql, params=(), fetch=None, **_kwargs):
        normalized = " ".join(str(sql).split()).lower()
        if "select snapshot_id from permission_audit_snapshots where snapshot_key=%s" in normalized:
            return (101,)
        if "select count(*) from permission_audit_apps where snapshot_id=%s" in normalized:
            return (0,) if calls["persist"] == 1 else (1,)
        return None

    monkeypatch.setattr(permission_flow, "generate_report", _fake_generate_report)
    monkeypatch.setattr(permission_flow, "collect_permissions_and_sdk", _fake_collect_permissions_and_sdk)
    monkeypatch.setattr(permission_flow, "render_permission_profile", _fake_render_permission_profile)
    monkeypatch.setattr(permission_flow.PermissionAuditAccumulator, "persist_to_db", _fake_persist_to_db)
    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", _fake_run_sql)
    monkeypatch.setattr(permission_flow, "create_static_run_ledger", lambda **_kwargs: 202)
    monkeypatch.setattr(permission_flow, "finalize_static_run", lambda **_kwargs: None)

    permission_flow.execute_permission_scan(selection, params, persist_detections=True)

    assert calls["persist"] == 2


def test_permission_flow_raises_when_snapshot_header_has_no_app_rows_after_retry(tmp_path, monkeypatch):
    selection = _make_selection(tmp_path)
    params = RunParameters(profile="permissions", scope="app", scope_label="Example app")

    def _fake_generate_report(_artifact, _base_dir, _params):
        return _FakeReport(manifest=_FakeManifest()), None, None, False

    def _fake_collect_permissions_and_sdk(_path):
        return [("android.permission.CAMERA", "framework")], {}, {"target_sdk": 35}

    def _fake_render_permission_profile(*_args, **_kwargs):
        return {"risk_counts": {"dangerous": 1, "signature": 0}, "V": 0, "score_detail": {"score_raw": 1}}

    def _fake_persist_to_db(_payload):
        return OperationResult.success()

    def _fake_run_sql(sql, params=(), fetch=None, **_kwargs):
        normalized = " ".join(str(sql).split()).lower()
        if "select snapshot_id from permission_audit_snapshots where snapshot_key=%s" in normalized:
            return (101,)
        if "select count(*) from permission_audit_apps where snapshot_id=%s" in normalized:
            return (0,)
        return None

    monkeypatch.setattr(permission_flow, "generate_report", _fake_generate_report)
    monkeypatch.setattr(permission_flow, "collect_permissions_and_sdk", _fake_collect_permissions_and_sdk)
    monkeypatch.setattr(permission_flow, "render_permission_profile", _fake_render_permission_profile)
    monkeypatch.setattr(permission_flow.PermissionAuditAccumulator, "persist_to_db", _fake_persist_to_db)
    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", _fake_run_sql)
    monkeypatch.setattr(permission_flow, "create_static_run_ledger", lambda **_kwargs: 202)
    monkeypatch.setattr(permission_flow, "finalize_static_run", lambda **_kwargs: None)

    import pytest

    with pytest.raises(RuntimeError, match="Permission audit persistence incomplete"):
        permission_flow.execute_permission_scan(
            selection,
            params,
            persist_detections=True,
            fail_on_persist_error=True,
        )
