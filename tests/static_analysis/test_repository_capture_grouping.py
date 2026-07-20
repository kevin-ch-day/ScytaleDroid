from __future__ import annotations

import json
from pathlib import Path

import pytest
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.StaticAnalysis.core.repository import (
    discover_repository_artifacts,
    group_artifacts,
)


def _write_artifact(
    root: Path,
    *,
    day: str,
    package: str,
    filename: str,
    metadata: dict[str, object],
) -> None:
    pkg_dir = root / day / package
    pkg_dir.mkdir(parents=True, exist_ok=True)
    apk_path = pkg_dir / filename
    apk_path.write_text("apk", encoding="utf-8")
    meta_path = apk_path.with_suffix(apk_path.suffix + ".meta.json")
    meta_path.write_text(json.dumps(metadata), encoding="utf-8")


def test_grouping_is_capture_bounded_for_same_split_group(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    package = "com.zhiliaoapp.musically"

    for day, version in (("20260207", "2024307030"), ("20260217", "2024309030")):
        base_meta = {
            "package_name": package,
            "version_code": version,
            "split_group_id": 72,
            "session_stamp": day,
            "artifact": "base",
            "is_split_member": False,
        }
        split_meta = {
            **base_meta,
            "artifact": "split_config.arm64_v8a",
            "is_split_member": True,
        }
        _write_artifact(
            root,
            day=day,
            package=package,
            filename=f"{package}_{version}__base.apk",
            metadata=base_meta,
        )
        _write_artifact(
            root,
            day=day,
            package=package,
            filename=f"{package}_{version}__split_config.arm64_v8a.apk",
            metadata=split_meta,
        )

    groups = [g for g in group_artifacts(root) if g.package_name == package]
    assert len(groups) == 2
    assert sorted(len(g.artifacts) for g in groups) == [2, 2]
    assert sorted(g.capture_id for g in groups) == ["20260207", "20260217"]


def test_path_discovery_ignores_package_directory_ending_in_apk(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    package_dir = root / "run1" / "com.google.android.appsearch.apk" / "com.google.android.appsearch.apk_v37_17"
    package_dir.mkdir(parents=True)
    (package_dir / "harvest_package_manifest.json").write_text("{}", encoding="utf-8")
    apk_path = root / "run1" / "com.example.real" / "Real_v1" / "base.apk"
    apk_path.parent.mkdir(parents=True)
    apk_path.write_text("apk", encoding="utf-8")

    artifacts = discover_repository_artifacts(root)

    assert [artifact.path for artifact in artifacts] == [apk_path]


def test_capture_id_fallback_uses_path_date_token_when_session_missing(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    package = "com.example.app"
    common = {
        "package_name": package,
        "version_code": "1",
        "split_group_id": 11,
        "artifact": "base",
    }

    _write_artifact(
        root,
        day="20260101",
        package=package,
        filename="app_v1_base.apk",
        metadata={**common, "snapshot_captured_at": "2026-01-01T12:00:00Z"},
    )
    _write_artifact(
        root,
        day="20260201",
        package=package,
        filename="app_v1_base_other.apk",
        metadata={**common, "snapshot_captured_at": "2026-02-01T12:00:00Z"},
    )

    groups = [g for g in group_artifacts(root) if g.package_name == package]
    assert len(groups) == 2
    assert sorted(g.capture_id for g in groups) == ["legacy-20260101", "legacy-20260201"]


def test_grouping_loads_harvest_package_manifest(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    package = "com.example.manifested"
    day = "20260328"
    metadata = {
        "package_name": package,
        "version_code": "101",
        "version_name": "1.0.1",
        "split_group_id": 55,
        "session_stamp": day,
        "artifact": "base",
        "is_split_member": False,
    }
    _write_artifact(
        root,
        day=day,
        package=package,
        filename="base.apk",
        metadata=metadata,
    )
    manifest_path = root / day / package / "harvest_package_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "harvest_package_manifest_v1",
                "execution_state": "completed",
                "status": {
                    "capture_status": "clean",
                    "persistence_status": "mirror_failed",
                    "research_status": "pending_audit",
                },
                "comparison": {
                    "matches_planned_artifacts": True,
                    "observed_hashes_complete": True,
                },
            }
        ),
        encoding="utf-8",
    )

    groups = [g for g in group_artifacts(root) if g.package_name == package]

    assert len(groups) == 1
    group = groups[0]
    assert group.harvest_manifest_path == str(manifest_path)
    assert group.harvest_capture_status == "clean"
    assert group.harvest_persistence_status == "mirror_failed"
    assert group.harvest_research_status == "pending_audit"
    assert group.matches_planned_artifacts is True
    assert group.observed_hashes_complete is True
    assert group.harvest_research_usable is True


def test_grouping_loads_receipt_backed_artifacts(tmp_path: Path) -> None:
    sha256 = "f" * 64
    canonical_apk = tmp_path / "data" / "store" / "apk" / "sha256" / "ff" / f"{sha256}.apk"
    canonical_apk.parent.mkdir(parents=True, exist_ok=True)
    canonical_apk.write_text("apk", encoding="utf-8")
    receipt_root = tmp_path / "data" / "receipts" / "harvest"
    receipt_path = receipt_root / "20260328-rda-full" / "com.example.receipt.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(
        json.dumps(
            {
                "schema": "harvest_package_manifest_v1",
                "generated_at_utc": "2026-03-28T10:00:00Z",
                "execution_state": "completed",
                "package": {
                    "package_name": "com.example.receipt",
                    "app_label": "Receipt Example",
                    "version_name": "1.0.1",
                    "version_code": "101",
                    "session_label": "20260328-rda-full",
                },
                "inventory": {
                    "installer": "com.android.vending",
                    "category": "Social media",
                },
                "execution": {
                    "observed_artifacts": [
                        {
                            "split_label": "base",
                            "file_name": canonical_apk.name,
                            "is_base": True,
                            "canonical_store_path": canonical_apk.relative_to(tmp_path).as_posix(),
                            "sha256": sha256,
                            "file_size": 3,
                            "observed_source_path": "/data/app/example/base.apk",
                            "pull_outcome": "written",
                        }
                    ]
                },
                "status": {
                    "capture_status": "clean",
                    "persistence_status": "mirrored",
                    "research_status": "pending_audit",
                },
                "comparison": {
                    "matches_planned_artifacts": True,
                    "observed_hashes_complete": True,
                },
            }
        ),
        encoding="utf-8",
    )

    cwd = Path.cwd()
    try:
        import os

        os.chdir(tmp_path)
        groups = group_artifacts(receipt_root)
    finally:
        os.chdir(cwd)

    assert len(groups) == 1
    group = groups[0]
    assert group.package_name == "com.example.receipt"
    assert group.harvest_manifest_path is not None
    resolved_manifest_path = Path(group.harvest_manifest_path)
    if not resolved_manifest_path.is_absolute():
        resolved_manifest_path = (tmp_path / resolved_manifest_path).resolve()
    assert resolved_manifest_path == receipt_path.resolve()
    assert group.artifacts[0].path == canonical_apk.resolve()
    assert group.harvest_capture_status == "clean"


def test_artifacts_from_receipt_preserve_device_serial(tmp_path: Path) -> None:
    apk_path = tmp_path / "signal.apk"
    apk_path.write_bytes(b"apk")
    meta_path = apk_path.with_suffix(".apk.meta.json")
    meta_path.write_text(json.dumps({"sha256": "abc123"}), encoding="utf-8")

    receipt_path = tmp_path / "receipt.json"
    payload = {
        "package": {
            "package_name": "org.thoughtcrime.securesms",
            "app_label": "Signal",
            "device_serial": "ZY22JK89DR",
            "session_label": "20260427",
            "version_name": "8.6.2",
            "version_code": "167501",
        },
        "inventory": {
            "installer": "com.android.vending",
            "category": "Messaging",
            "profile_key": "RESEARCH_DATASET_ALPHA",
            "profile_name": "Research Dataset Alpha",
        },
        "execution": {
            "observed_artifacts": [
                {
                    "file_name": "signal.apk",
                    "sha256": "abc123",
                    "is_base": True,
                    "canonical_store_path": str(apk_path),
                }
            ]
        },
        "generated_at_utc": "2026-04-27T14:49:21Z",
    }

    from scytaledroid.StaticAnalysis.core import repository

    artifacts = repository._artifacts_from_receipt(receipt_path, payload)

    assert len(artifacts) == 1
    assert artifacts[0].metadata["device_serial"] == "ZY22JK89DR"


def _write_receipt_for_canonical_blob(receipt_root: Path, *, sha256: str) -> Path:
    receipt_path = receipt_root / "20260328-rda-full" / "com.example.cold.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(
        json.dumps(
            {
                "schema": "harvest_package_manifest_v1",
                "generated_at_utc": "2026-03-28T10:00:00Z",
                "execution_state": "completed",
                "package": {
                    "package_name": "com.example.cold",
                    "app_label": "Cold Example",
                    "version_name": "1.0.1",
                    "version_code": "101",
                    "session_label": "20260328-rda-full",
                },
                "inventory": {
                    "installer": "com.android.vending",
                    "category": "Social media",
                },
                "execution": {
                    "observed_artifacts": [
                        {
                            "split_label": "base",
                            "file_name": f"{sha256}.apk",
                            "is_base": True,
                            "canonical_store_path": f"data/store/apk/sha256/{sha256[:2]}/{sha256}.apk",
                            "sha256": sha256,
                            "file_size": 3,
                            "observed_source_path": "/data/app/example/base.apk",
                            "pull_outcome": "library_hit",
                        }
                    ]
                },
                "status": {
                    "capture_status": "clean",
                    "persistence_status": "mirrored",
                    "research_status": "pending_audit",
                },
                "comparison": {
                    "matches_planned_artifacts": True,
                    "observed_hashes_complete": True,
                },
            }
        ),
        encoding="utf-8",
    )
    return receipt_path


def test_receipt_backed_cold_blob_fails_clearly_when_mercury_unmounted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sha256 = "a" * 64
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_apk = external_mount / "cold" / "data" / "store" / "apk" / "sha256" / "aa" / f"{sha256}.apk"
    cold_apk.parent.mkdir(parents=True, exist_ok=True)
    cold_apk.write_text("apk", encoding="utf-8")
    canonical_link = tmp_path / "data" / "store" / "apk" / "sha256" / "aa" / f"{sha256}.apk"
    canonical_link.parent.mkdir(parents=True, exist_ok=True)
    canonical_link.symlink_to(cold_apk)
    receipt_root = tmp_path / "data" / "receipts" / "harvest"
    _write_receipt_for_canonical_blob(receipt_root, sha256=sha256)
    monkeypatch.setattr(artifact_store, "EXTERNAL_APK_STORE_MOUNT_ROOTS", (external_mount,))
    monkeypatch.setattr(artifact_store.os.path, "ismount", lambda _path: False)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(artifact_store.ColdApkBlobUnavailable, match="Mercury drive is not mounted"):
        group_artifacts(receipt_root)


def test_receipt_backed_cold_blob_resolves_when_mercury_mounted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sha256 = "b" * 64
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_apk = external_mount / "cold" / "data" / "store" / "apk" / "sha256" / "bb" / f"{sha256}.apk"
    cold_apk.parent.mkdir(parents=True, exist_ok=True)
    cold_apk.write_text("apk", encoding="utf-8")
    canonical_link = tmp_path / "data" / "store" / "apk" / "sha256" / "bb" / f"{sha256}.apk"
    canonical_link.parent.mkdir(parents=True, exist_ok=True)
    canonical_link.symlink_to(cold_apk)
    receipt_root = tmp_path / "data" / "receipts" / "harvest"
    _write_receipt_for_canonical_blob(receipt_root, sha256=sha256)
    monkeypatch.setattr(artifact_store, "EXTERNAL_APK_STORE_MOUNT_ROOTS", (external_mount,))
    monkeypatch.setattr(artifact_store.os.path, "ismount", lambda path: Path(path) == external_mount)
    monkeypatch.chdir(tmp_path)

    groups = group_artifacts(receipt_root)

    assert len(groups) == 1
    assert groups[0].artifacts[0].path == cold_apk.resolve()
