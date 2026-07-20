from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services import artifact_store


def test_materialize_apk_moves_into_canonical_store(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")

    source = tmp_path / "data" / "inbox" / "uploads" / "upload.apk"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"apk-bytes")
    digest = "a" * 64

    stored = artifact_store.materialize_apk(
        source,
        sha256_digest=digest,
        move=True,
    )

    expected = tmp_path / "data" / "store" / "apk" / "sha256" / "aa" / f"{digest}.apk"
    assert stored == expected
    assert stored.exists()
    assert not source.exists()


def test_materialize_apk_reuses_existing_store_copy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")

    digest = "b" * 64
    stored = artifact_store.canonical_apk_path(digest)
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_bytes(b"first-copy")

    source = tmp_path / "second.apk"
    source.write_bytes(b"second-copy")

    resolved = artifact_store.materialize_apk(source, sha256_digest=digest, move=True)

    assert resolved == stored.resolve()
    assert stored.read_bytes() == b"first-copy"
    assert not source.exists()


def test_write_receipts_use_stable_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")

    harvest_path = artifact_store.write_harvest_receipt(
        session_label="20260328-rda-full",
        package_name="com.example.app",
        payload={"schema": "test"},
    )
    upload_path = artifact_store.write_upload_receipt(
        upload_id="upload-1",
        payload={"schema": "upload"},
    )

    assert harvest_path == (
        tmp_path / "data" / "receipts" / "harvest" / "20260328-rda-full" / "com.example.app.json"
    )
    assert upload_path == tmp_path / "data" / "receipts" / "upload" / "upload-1.json"
    assert harvest_path.exists()
    assert upload_path.exists()


def test_safe_filesystem_slug_sanitizes_like_receipt_paths() -> None:
    assert artifact_store.safe_filesystem_slug("com.example.app") == "com.example.app"
    assert artifact_store.safe_filesystem_slug("weird/name!") == "weird-name"
    assert artifact_store.safe_filesystem_slug("  trim  ") == "trim"


def test_repo_relative_path_keeps_canonical_store_logical_when_symlinked(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")

    digest = "c" * 64
    external = tmp_path / "mnt" / "MERCURY_DATA_V2" / "active" / "data" / "store" / "apk"
    canonical = external / "sha256" / digest[:2] / f"{digest}.apk"
    canonical.parent.mkdir(parents=True)
    canonical.write_bytes(b"apk")
    local_apk_root = tmp_path / "data" / "store" / "apk"
    local_apk_root.parent.mkdir(parents=True)
    local_apk_root.symlink_to(external)

    assert artifact_store.repo_relative_path(canonical) == f"data/store/apk/sha256/{digest[:2]}/{digest}.apk"


def test_repo_relative_path_maps_absolute_mercury_cold_blob_to_logical_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    monkeypatch.setattr(artifact_store, "EXTERNAL_APK_STORE_MOUNT_ROOTS", (external_mount,))

    digest = "1" * 64
    cold_blob = external_mount / "scytaledroid_artifacts" / "apk_store" / "cold" / "data" / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"

    assert artifact_store.repo_relative_path(cold_blob) == f"data/store/apk/sha256/{digest[:2]}/{digest}.apk"


def test_materialize_apk_refuses_unmounted_external_symlink(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    external_store = external_mount / "active" / "data" / "store" / "apk"
    local_apk_root = tmp_path / "data" / "store" / "apk"
    local_apk_root.parent.mkdir(parents=True)
    local_apk_root.symlink_to(external_store)
    source = tmp_path / "upload.apk"
    source.write_bytes(b"apk")

    monkeypatch.setattr(artifact_store, "EXTERNAL_APK_STORE_MOUNT_ROOTS", (external_mount,))
    monkeypatch.setattr(artifact_store.os.path, "ismount", lambda _path: False)

    with pytest.raises(artifact_store.ExternalApkStoreUnavailable, match="External APK store is configured but not mounted"):
        artifact_store.materialize_apk(source, sha256_digest="d" * 64)


def test_materialize_apk_refuses_broken_cold_blob_symlink(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    digest = "e" * 64
    cold_target = external_mount / "cold" / "data" / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"
    local_blob = artifact_store.canonical_apk_path(digest)
    local_blob.parent.mkdir(parents=True)
    local_blob.symlink_to(cold_target)
    source = tmp_path / "upload.apk"
    source.write_bytes(b"apk")

    monkeypatch.setattr(artifact_store, "EXTERNAL_APK_STORE_MOUNT_ROOTS", (external_mount,))
    monkeypatch.setattr(artifact_store.os.path, "ismount", lambda path: Path(path) == external_mount)

    with pytest.raises(artifact_store.ColdApkBlobUnavailable, match="canonical APK symlink target is missing"):
        artifact_store.materialize_apk(source, sha256_digest=digest)


def test_materialize_apk_reuses_available_cold_blob_symlink(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    digest = "f" * 64
    cold_target = external_mount / "cold" / "data" / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"
    cold_target.parent.mkdir(parents=True)
    cold_target.write_bytes(b"cold")
    local_blob = artifact_store.canonical_apk_path(digest)
    local_blob.parent.mkdir(parents=True)
    local_blob.symlink_to(cold_target)
    source = tmp_path / "upload.apk"
    source.write_bytes(b"new-copy")

    monkeypatch.setattr(artifact_store, "EXTERNAL_APK_STORE_MOUNT_ROOTS", (external_mount,))
    monkeypatch.setattr(artifact_store.os.path, "ismount", lambda path: Path(path) == external_mount)

    resolved = artifact_store.materialize_apk(source, sha256_digest=digest, move=True)

    assert resolved == local_blob
    assert artifact_store.repo_relative_path(resolved) == f"data/store/apk/sha256/{digest[:2]}/{digest}.apk"
    assert cold_target.read_bytes() == b"cold"
    assert not source.exists()
