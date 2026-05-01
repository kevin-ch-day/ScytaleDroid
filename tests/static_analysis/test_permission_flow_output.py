from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.execution import analytics, permission_flow
from scytaledroid.StaticAnalysis.cli.persistence import metrics_writer
from scytaledroid.StaticAnalysis.modules.permissions import permission_console_rendering
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


@dataclass
class _FakeManifestFlags:
    allow_backup: bool | None = False
    request_legacy_external_storage: bool | None = False


@dataclass
class _ConsoleReport:
    manifest: _FakeManifest
    manifest_flags: _FakeManifestFlags
    detector_metrics: dict


@dataclass
class _DeclaredPermissions:
    declared: list[str]
    custom_definitions: dict | None = None


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


def test_permission_flow_reuses_report_permission_metadata_before_apk_reextract(tmp_path, monkeypatch):
    selection = _make_selection(tmp_path)
    params = RunParameters(profile="permissions", scope="profile", scope_label="Example profile")
    seen_sdk: list[dict[str, str | None]] = []

    report = _ConsoleReport(
        manifest=_FakeManifest(target_sdk=35, min_sdk=23),
        manifest_flags=_FakeManifestFlags(allow_backup=False, request_legacy_external_storage=False),
        detector_metrics={},
    )
    report.permissions = _DeclaredPermissions(
        declared=["android.permission.CAMERA"],
        custom_definitions={"com.example.permission.TEST": {"protection": "signature"}},
    )

    def _fake_generate_report(_artifact, _base_dir, _params):
        return report, None, None, False

    def _unexpected_collect(_path):
        raise AssertionError("collect_permissions_and_sdk should not run when report already has permission metadata")

    def _fake_render_permission_profile(*_args, **kwargs):
        seen_sdk.append(dict(kwargs.get("sdk") or {}))
        return {"risk_counts": {"dangerous": 1, "signature": 0}, "V": 0, "score_detail": {"score_raw": 1}}

    monkeypatch.setattr(permission_flow, "generate_report", _fake_generate_report)
    monkeypatch.setattr(permission_flow, "collect_permissions_and_sdk", _unexpected_collect)
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

    assert seen_sdk
    assert seen_sdk[0]["min"] == 23
    assert seen_sdk[0]["target"] == 35


def test_permission_postcard_uses_detector_penalty_inputs(monkeypatch):
    monkeypatch.setattr(
        permission_console_rendering,
        "_fetch_protections",
        lambda *_a, **_k: {},
    )
    monkeypatch.setattr(
        permission_console_rendering,
        "_classify_permissions",
        lambda *_a, **_k: (
            {"dangerous": 9, "signature": 0},
            {"CAM": 2, "MIC": 2, "CNT": 2, "STR": 2, "OVR": 2, "NOT": 2},
            {"ADS": 2},
            set(),
            set(),
        ),
    )

    report = _ConsoleReport(
        manifest=_FakeManifest(target_sdk=35),
        manifest_flags=_FakeManifestFlags(allow_backup=False, request_legacy_external_storage=False),
        detector_metrics={
            "permissions_profile": {
                "permission_profiles": {
                    "android.permission.RECEIVE_BOOT_COMPLETED": {
                        "is_flagged_normal": True,
                        "flagged_normal_class": "noteworthy_normal",
                    },
                    "android.permission.SYSTEM_ALERT_WINDOW": {
                        "is_runtime_dangerous": True,
                        "guard_strength": "weak",
                    },
                }
            }
        },
    )

    profile = permission_console_rendering.render_permission_postcard(
        "com.example.app",
        "Example",
        [("android.permission.CAMERA", "framework")],
        [],
        sdk={"target_sdk": 35},
        report=report,
        index=1,
        total=1,
        compact=True,
        silent=True,
    )

    detail = profile["score_detail"]
    assert detail["flagged_normal_count"] == 1
    assert detail["noteworthy_normal_count"] == 1
    assert detail["special_risk_normal_count"] == 0
    assert detail["weak_guard_count"] == 1
    assert detail["modernization_credit"] == 0.8
    assert detail["penalty_components"]["noteworthy_normal"] == 0.06
    assert detail["penalty_components"]["flagged_normal"] == 0.06
    assert detail["penalty_components"]["weak_guard"] == 0.08


def test_permission_profiles_and_metrics_prefer_manifest_extraction(monkeypatch):
    report = _ConsoleReport(
        manifest=_FakeManifest(target_sdk=35),
        manifest_flags=_FakeManifestFlags(allow_backup=False, request_legacy_external_storage=False),
        detector_metrics={},
    )
    report.permissions = _DeclaredPermissions(
        declared=["android.permission.CAMERA", "android.permission.RECORD_AUDIO"]
    )
    report.file_path = "/tmp/example.apk"
    report.exported_components = type("_Exported", (), {"total": lambda self: 0})()

    extracted_declared = [
        ("android.permission.CAMERA", "uses-permission"),
        ("android.permission.RECORD_AUDIO", "uses-permission"),
        ("android.permission.READ_CONTACTS", "uses-permission"),
        ("android.permission.ACCESS_FINE_LOCATION", "uses-permission"),
    ]

    def _fake_collect_permissions_and_sdk(_path):
        return extracted_declared, [], {"target": 35, "allow_backup": False, "legacy_external_storage": False}

    monkeypatch.setattr(
        permission_console_rendering,
        "collect_permissions_and_sdk",
        _fake_collect_permissions_and_sdk,
    )
    monkeypatch.setattr(
        analytics,
        "_perm_fetch_protections",
        lambda shorts, target_sdk=None: {str(item): "dangerous" for item in shorts},
    )
    monkeypatch.setattr(
        metrics_writer,
        "_prot_map",
        lambda shorts, target_sdk=None: {str(item): "dangerous" for item in shorts},
    )

    profile = analytics._build_permission_profile(report, type("_App", (), {"package_name": "com.example.app"})())
    bundle = metrics_writer.compute_metrics_bundle(report, {})

    assert profile["D"] == 4
    assert int(bundle.permission_detail["dangerous_count"]) == 4
