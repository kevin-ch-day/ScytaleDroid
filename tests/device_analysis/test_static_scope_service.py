from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scytaledroid.DeviceAnalysis.services.static_scope_service import StaticScopeService


@dataclass
class FakeArtifact:
    path: Path


@dataclass
class FakeGroup:
    artifacts: tuple[FakeArtifact, ...]


def test_static_scope_service_persists_selection_manifest(tmp_path):
    manifest_path = tmp_path / "library_selection.json"
    apk_path = tmp_path / "device_apks" / "app" / "base.apk"

    service = StaticScopeService(manifest_path=manifest_path)
    service.select_paths([str(apk_path)])

    reloaded = StaticScopeService(manifest_path=manifest_path)

    assert reloaded.count() == 1
    assert reloaded.is_selected(str(apk_path))
    assert manifest_path.exists()


def test_static_scope_service_persists_group_selection_and_clear_removes_manifest(tmp_path):
    manifest_path = tmp_path / "library_selection.json"
    artifact_a = FakeArtifact(tmp_path / "device_apks" / "pkg.alpha" / "base.apk")
    artifact_b = FakeArtifact(tmp_path / "device_apks" / "pkg.alpha" / "split_config.en.apk")
    group = FakeGroup((artifact_a, artifact_b))

    service = StaticScopeService(manifest_path=manifest_path)
    service.select_group(group)

    assert service.count() == 2
    assert service.is_group_selected(group)

    service.clear()

    assert service.count() == 0
    assert not manifest_path.exists()


def test_static_scope_service_removes_group_paths(tmp_path):
    manifest_path = tmp_path / "library_selection.json"
    artifact_a = FakeArtifact(tmp_path / "device_apks" / "pkg.alpha" / "base.apk")
    artifact_b = FakeArtifact(tmp_path / "device_apks" / "pkg.alpha" / "split_config.en.apk")
    group = FakeGroup((artifact_a, artifact_b))

    service = StaticScopeService(manifest_path=manifest_path)
    service.select_group(group)
    service.remove_group(group)

    assert service.count() == 0
    assert service.get_selected() == []


def test_static_scope_service_prunes_stale_paths(tmp_path):
    manifest_path = tmp_path / "library_selection.json"
    keep_path = tmp_path / "device_apks" / "pkg.alpha" / "base.apk"
    stale_path = tmp_path / "device_apks" / "pkg.beta" / "base.apk"

    service = StaticScopeService(manifest_path=manifest_path)
    service.select_paths([str(keep_path), str(stale_path)])

    removed = service.prune_missing_paths([str(keep_path)])

    assert removed == 1
    assert service.count() == 1
    assert service.get_selected() == [str(keep_path.resolve(strict=False))]
