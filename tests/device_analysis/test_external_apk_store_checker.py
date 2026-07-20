from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest
from scripts.device_analysis import check_external_apk_store_mount as checker

pytestmark = [pytest.mark.unit]


def _write_canonical(root: Path, payload: bytes = b"apk") -> str:
    digest = hashlib.sha256(payload).hexdigest()
    path = root / "sha256" / digest[:2] / f"{digest}.apk"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return digest


def test_checker_reports_ok_for_mounted_external_store(tmp_path: Path) -> None:
    data = tmp_path / "repo" / "data"
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    external_apk = external_mount / "active" / "data" / "store" / "apk"
    external_android = external_mount / "active" / "data" / "android_apks"
    _write_canonical(external_apk)
    external_android.mkdir(parents=True)

    local_apk = data / "store" / "apk"
    local_apk.parent.mkdir(parents=True)
    local_apk.symlink_to(external_apk)
    local_android = data / "android_apks"
    local_android.symlink_to(external_android)

    report = checker.build_report(
        data_root=data,
        mount_roots=[external_mount],
        verify_sha256=True,
        is_mount=lambda path: Path(path) == external_mount,
    )

    assert report["status"] == "OK"
    assert report["data_store_apk"]["is_symlink"] is True
    assert report["data_store_apk"]["external_mount_mounted"] is True
    assert report["canonical_store"]["canonical_apk_blob_count"] == 1
    assert report["canonical_store"]["sha_filename_mismatch_count"] == 0


def test_checker_reports_blocked_for_unmounted_external_store(tmp_path: Path) -> None:
    data = tmp_path / "repo" / "data"
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    external_apk = external_mount / "active" / "data" / "store" / "apk"
    local_apk = data / "store" / "apk"
    local_apk.parent.mkdir(parents=True)
    local_apk.symlink_to(external_apk)

    report = checker.build_report(
        data_root=data,
        mount_roots=[external_mount],
        verify_sha256=False,
        is_mount=lambda _path: False,
    )

    assert report["status"] == "BLOCKED"
    assert "External APK store is configured but not mounted." in report["findings"]


def test_checker_reports_broken_legacy_apk_symlinks(tmp_path: Path) -> None:
    data = tmp_path / "repo" / "data"
    apk_root = data / "store" / "apk"
    _write_canonical(apk_root)
    broken = data / "device_apks" / "SER1" / "runs" / "run-1" / "pkg" / "base.apk"
    broken.parent.mkdir(parents=True)
    broken.symlink_to(tmp_path / "missing.apk")

    report = checker.build_report(
        data_root=data,
        serial="SER1",
        verify_sha256=False,
    )

    assert report["status"] == "WARN"
    assert report["legacy_device_apks"]["broken_apk_symlink_count"] == 1


def test_checker_counts_available_cold_canonical_symlink(tmp_path: Path) -> None:
    data = tmp_path / "repo" / "data"
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    digest = "a" * 64
    cold_target = external_mount / "cold" / "data" / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"
    cold_target.parent.mkdir(parents=True)
    cold_target.write_bytes(b"cold-apk")
    local_blob = data / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"
    local_blob.parent.mkdir(parents=True)
    local_blob.symlink_to(cold_target)

    report = checker.build_report(
        data_root=data,
        mount_roots=[external_mount],
        verify_sha256=False,
        is_mount=lambda path: Path(path) == external_mount,
    )

    canonical = report["canonical_store"]
    assert report["status"] == "WARN"
    assert canonical["canonical_apk_blob_count"] == 1
    assert canonical["local_hot_regular_blob_count"] == 0
    assert canonical["cold_symlink_blob_count"] == 1
    assert canonical["broken_canonical_symlink_count"] == 0
    assert canonical["cold_referenced_bytes"] == len(b"cold-apk")


def test_checker_blocks_unmounted_cold_canonical_symlink(tmp_path: Path) -> None:
    data = tmp_path / "repo" / "data"
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    digest = "b" * 64
    cold_target = external_mount / "cold" / "data" / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"
    local_blob = data / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"
    local_blob.parent.mkdir(parents=True)
    local_blob.symlink_to(cold_target)

    report = checker.build_report(
        data_root=data,
        mount_roots=[external_mount],
        verify_sha256=False,
        is_mount=lambda _path: False,
    )

    canonical = report["canonical_store"]
    assert report["status"] == "BLOCKED"
    assert canonical["cold_symlink_blob_count"] == 1
    assert canonical["broken_canonical_symlink_count"] == 1
    assert canonical["unavailable_cold_blob_count"] == 1


def test_checker_blocks_canonical_symlink_outside_allowed_roots(tmp_path: Path) -> None:
    data = tmp_path / "repo" / "data"
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    outside = tmp_path / "other" / "blob.apk"
    outside.parent.mkdir()
    outside.write_bytes(b"outside")
    digest = "c" * 64
    local_blob = data / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"
    local_blob.parent.mkdir(parents=True)
    local_blob.symlink_to(outside)

    report = checker.build_report(
        data_root=data,
        mount_roots=[external_mount],
        verify_sha256=False,
        is_mount=lambda _path: False,
    )

    assert report["status"] == "BLOCKED"
    assert report["canonical_store"]["canonical_symlink_outside_allowed_roots_count"] == 1


def test_checker_sha_progress_reports_canonical_path_count(tmp_path: Path) -> None:
    data = tmp_path / "repo" / "data"
    apk_root = data / "store" / "apk"
    _write_canonical(apk_root, b"one")
    _write_canonical(apk_root, b"two")
    progress = io.StringIO()

    report = checker.build_report(
        data_root=data,
        verify_sha256=True,
        progress_every=1,
        progress_stream=progress,
    )

    assert report["status"] == "OK"
    lines = progress.getvalue().strip().splitlines()
    assert len(lines) == 2
    assert lines[-1] == "SHA progress: 2/2 canonical APK paths; mismatches=0"
