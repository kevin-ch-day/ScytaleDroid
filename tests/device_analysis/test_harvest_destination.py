"""Harvest artifact layout helpers (session dirs, path normalization)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from scytaledroid.Config import app_config


def test_compose_harvest_run_destination_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))

    from scytaledroid.DeviceAnalysis.services import artifact_store

    run_id = "ABC12-20300416-123456-789012"
    dest, stamp = artifact_store.compose_harvest_run_destination(serial="ABC12", run_id=run_id)
    assert stamp == artifact_store.filesystem_harvest_run_label(run_id)
    assert dest == tmp_path / "data" / "device_apks" / "ABC12" / "runs" / stamp


def test_normalise_local_path_preserves_session_tree_for_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))

    from scytaledroid.DeviceAnalysis.harvest.common import normalise_local_path

    session_apk = (
        tmp_path
        / "data"
        / "device_apks"
        / "SER"
        / "runs"
        / "SER-20990101-120000-000001"
        / "pkg"
        / "AppName_v42_1.0"
        / "app.apk"
    )
    session_apk.parent.mkdir(parents=True, exist_ok=True)
    canon = tmp_path / "data" / "store" / "apk" / "sha256" / "aa" / "aabbcc.apk"
    canon.parent.mkdir(parents=True, exist_ok=True)
    canon.write_bytes(b"x")
    session_apk.symlink_to(Path(os.path.relpath(canon, session_apk.parent)))

    assert (
        normalise_local_path(session_apk)
        == "SER/runs/SER-20990101-120000-000001/pkg/AppName_v42_1.0/app.apk"
    )


def test_run_artifacts_root_fallback_nested_and_legacy_and_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))

    from scytaledroid.DeviceAnalysis.harvest.models import HarvestResult
    from scytaledroid.DeviceAnalysis.harvest.summary import _run_artifacts_root

    nested = HarvestResult(serial="X", run_timestamp="20300416_120000_000001")
    legacy_day = HarvestResult(serial="X", run_timestamp="20300416")
    runcentric = HarvestResult(serial="Y", run_timestamp="Y-20990101-120000-000099")

    assert _run_artifacts_root(serial="X", result=nested) == str(
        (tmp_path / "data" / "device_apks" / "X" / "20300416" / "120000_000001").resolve()
    )
    assert _run_artifacts_root(serial="X", result=legacy_day) == str(
        (tmp_path / "data" / "device_apks" / "X" / "20300416").resolve()
    )
    assert _run_artifacts_root(serial="Y", result=runcentric) == str(
        (tmp_path / "data" / "device_apks" / "Y" / "runs" / "Y-20990101-120000-000099").resolve()
    )


def test_package_evidence_dir_includes_app_and_version(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))

    from scytaledroid.DeviceAnalysis.harvest.common import package_evidence_dir, package_evidence_leaf_name
    from scytaledroid.DeviceAnalysis.harvest.models import InventoryRow

    inv = InventoryRow(
        raw={},
        package_name="com.example.app",
        app_label="Example App",
        installer=None,
        category=None,
        primary_path="/data/app/com.example.app/base.apk",
        profile_key=None,
        profile=None,
        version_name="1.9.2-rc1",
        version_code="120",
        apk_paths=["/data/app/com.example.app/base.apk"],
        split_count=1,
    )
    leaf = package_evidence_leaf_name(inv)
    assert leaf.startswith("Example-App_v120_")
    assert "1-9-2-rc1" in leaf or "rc1" in leaf
    root = tmp_path / "session"
    d = package_evidence_dir(root, inv)
    assert d == root / "com.example.app" / leaf
