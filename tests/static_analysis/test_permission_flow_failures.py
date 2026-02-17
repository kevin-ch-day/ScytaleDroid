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
        "scytaledroid.Persistence.db_writer.create_run",
        lambda **_kwargs: 101,
    )
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
