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
    groups = []
    for idx, package in enumerate(("com.example.a", "com.example.b"), start=1):
        artifact_path = tmp_path / f"{package}__base.apk"
        artifact_path.write_text("stub", encoding="utf-8")
        artifact = RepositoryArtifact(
            path=artifact_path,
            display_path=str(artifact_path),
            metadata={"package_name": package, "version_name": "1.0"},
        )
        groups.append(
            ArtifactGroup(
                group_key=package,
                package_name=package,
                version_display="1.0",
                session_stamp=f"20260123-00000{idx}",
                capture_id=f"20260123-00000{idx}",
                artifacts=(artifact,),
            )
        )
    return ScopeSelection(scope="profile", label="Example profile", groups=tuple(groups))


def test_permission_flow_passes_progress_index_to_renderer(tmp_path, monkeypatch):
    selection = _make_selection(tmp_path)
    params = RunParameters(profile="permissions", scope="profile", scope_label="Example profile")
    seen: list[tuple[int, int]] = []

    def _fake_generate_report(_artifact, _base_dir, _params):
        return _FakeReport(manifest=_FakeManifest()), None, None, False

    def _fake_collect_permissions_and_sdk(_path):
        return [("android.permission.CAMERA", "framework")], {}, {"target_sdk": 35}

    def _fake_render_permission_profile(*_args, **kwargs):
        seen.append((int(kwargs.get("index", 0)), int(kwargs.get("total", 0))))
        return {"risk_counts": {"dangerous": 1, "signature": 0}, "V": 0, "score_detail": {"score_raw": 1}}

    monkeypatch.setattr(permission_flow, "generate_report", _fake_generate_report)
    monkeypatch.setattr(permission_flow, "collect_permissions_and_sdk", _fake_collect_permissions_and_sdk)
    monkeypatch.setattr(permission_flow, "render_permission_profile", _fake_render_permission_profile)
    monkeypatch.setattr(permission_flow.PermissionAuditAccumulator, "persist_to_db", lambda *_a, **_k: OperationResult.success())
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.persistence.permissions_db.persist_permissions_to_db",
        lambda *_a, **_k: {"aosp": 1, "oem": 0, "app_defined": 0, "unknown": 0},
    )

    permission_flow.execute_permission_scan(
        selection,
        params,
        persist_detections=True,
        compact_output=False,
    )

    assert seen == [(1, 2), (2, 2)]


def test_permission_flow_profile_scope_defaults_compact_and_aggregates_persist(tmp_path, monkeypatch):
    selection = _make_selection(tmp_path)
    params = RunParameters(profile="permissions", scope="profile", scope_label="Example profile")
    compact_notice_called: list[bool] = []
    persist_messages: list[dict | None] = []

    def _fake_generate_report(_artifact, _base_dir, _params):
        return _FakeReport(manifest=_FakeManifest()), None, None, False

    def _fake_collect_permissions_and_sdk(_path):
        return [("android.permission.CAMERA", "framework")], {}, {"target_sdk": 35}

    def _fake_render_permission_profile(*_args, **_kwargs):
        return {"risk_counts": {"dangerous": 1, "signature": 0}, "V": 0, "score_detail": {"score_raw": 1}}

    monkeypatch.setattr(permission_flow, "generate_report", _fake_generate_report)
    monkeypatch.setattr(permission_flow, "collect_permissions_and_sdk", _fake_collect_permissions_and_sdk)
    monkeypatch.setattr(permission_flow, "render_permission_profile", _fake_render_permission_profile)
    monkeypatch.setattr(permission_flow, "render_compact_notice", lambda: compact_notice_called.append(True))
    monkeypatch.setattr(permission_flow, "render_permission_persisted", lambda counts: persist_messages.append(counts))
    monkeypatch.setattr(permission_flow.PermissionAuditAccumulator, "persist_to_db", lambda *_a, **_k: OperationResult.success())
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.persistence.permissions_db.persist_permissions_to_db",
        lambda *_a, **_k: {"aosp": 1, "oem": 0, "app_defined": 0, "unknown": 0},
    )

    permission_flow.execute_permission_scan(
        selection,
        params,
        persist_detections=True,
        compact_output=None,
    )

    assert compact_notice_called
    assert len(persist_messages) == 1
    assert persist_messages[0] == {"aosp": 2, "oem": 0, "app_defined": 0, "unknown": 0}
