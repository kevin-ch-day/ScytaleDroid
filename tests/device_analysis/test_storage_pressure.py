from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path

from scytaledroid.DeviceAnalysis.services import storage_pressure


def _write_apk(path: Path, payload: bytes) -> tuple[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return sha256(payload).hexdigest(), len(payload)


def _canonical_path(root: Path, sha: str) -> Path:
    return root / "store" / "apk" / "sha256" / sha[:2] / f"{sha}.apk"


def _session_path(root: Path) -> Path:
    return root / "device_apks" / "DEV1" / "runs" / "RUN1" / "com.example.app" / "1" / "base.apk"


def _write_sidecar(apk_path: Path, *, root: Path, sha: str, size: int) -> None:
    rel_apk = apk_path.relative_to(root).as_posix()
    rel_canonical = _canonical_path(root, sha).relative_to(root).as_posix()
    apk_path.with_suffix(apk_path.suffix + ".meta.json").write_text(
        json.dumps(
            {
                "package_name": "com.example.app",
                "version_code": "1",
                "local_path": rel_apk,
                "canonical_store_path": rel_canonical,
                "sha256": sha,
                "file_size": size,
                "artifact": "base",
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _write_manifest(apk_path: Path, *, root: Path, sha: str, size: int) -> None:
    rel_apk = apk_path.relative_to(root).as_posix()
    (apk_path.parent / "harvest_package_manifest.json").write_text(
        json.dumps(
            {
                "schema": "harvest_package_manifest_v1",
                "package": {
                    "package_name": "com.example.app",
                    "version_code": "1",
                    "session_label": "RUN1",
                    "device_serial": "DEV1",
                },
                "execution": {
                    "observed_artifacts": [
                        {
                            "split_label": "base",
                            "file_name": apk_path.name,
                            "local_artifact_path": rel_apk,
                            "canonical_store_path": _canonical_path(root, sha).relative_to(root).as_posix(),
                            "sha256": sha,
                            "file_size": size,
                        }
                    ]
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def test_storage_pressure_marks_regular_session_apk_eligible_verified(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_apk = _session_path(root)
    apk_sha, size = _write_apk(session_apk, b"same-apk-bytes")
    _write_apk(_canonical_path(root, apk_sha), b"same-apk-bytes")
    _write_sidecar(session_apk, root=root, sha=apk_sha, size=size)
    _write_manifest(session_apk, root=root, sha=apk_sha, size=size)

    records, issues = storage_pressure.scan_session_copy_pressure(root=root, verify_candidates=True)
    assert issues == []
    assert len(records) == 1
    record = records[0]
    assert record.status == storage_pressure.STATUS_ELIGIBLE_VERIFIED
    assert record.session_copy_bytes_present is True
    assert record.canonical_bytes_available is True
    assert record.reclaimable_bytes == size

    audit = storage_pressure.build_storage_pressure_audit(
        root=root,
        session_records=records,
        canonical_summary=storage_pressure.scan_canonical_apk_store(root),
        verify_candidates=True,
    )
    assert audit["summary"]["session_regular_apk_files"] == 1
    assert audit["summary"]["eligible_verified_reclaimable_bytes"] == size


def test_storage_pressure_blocks_missing_canonical_payload(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_apk = _session_path(root)
    apk_sha, size = _write_apk(session_apk, b"session-only")
    _write_sidecar(session_apk, root=root, sha=apk_sha, size=size)
    _write_manifest(session_apk, root=root, sha=apk_sha, size=size)

    records, issues = storage_pressure.scan_session_copy_pressure(root=root, verify_candidates=True)
    assert issues == []
    assert records[0].status == storage_pressure.STATUS_BLOCKED_CANONICAL_MISSING
    assert records[0].reclaimable_bytes == 0


def test_storage_pressure_counts_existing_thin_symlink_without_payload_pressure(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_apk = _session_path(root)
    apk_sha, size = _write_apk(_canonical_path(root, "0" * 64), b"thin-target")
    canonical = _canonical_path(root, apk_sha)
    _write_apk(canonical, b"thin-target")
    session_apk.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(os.path.relpath(canonical, start=session_apk.parent), session_apk)
    _write_sidecar(session_apk, root=root, sha=apk_sha, size=size)
    _write_manifest(session_apk, root=root, sha=apk_sha, size=size)

    records, issues = storage_pressure.scan_session_copy_pressure(root=root, verify_candidates=True)
    assert issues == []
    assert records[0].status == storage_pressure.STATUS_ALREADY_THIN_SYMLINK
    assert records[0].session_rel_path.endswith("base.apk")
    assert records[0].session_copy_bytes_present is False
    assert records[0].reclaimable_bytes == 0


def test_storage_pressure_keeps_historical_identity_separate_from_session_pressure(tmp_path: Path) -> None:
    root = tmp_path / "data"
    historical = storage_pressure.DbArtifactIdentity(
        row_source="android_apk_repository",
        artifact_id="1",
        package_name="com.example.old",
        version_code="1",
        version_name="1.0",
        file_name="base.apk",
        file_size=123,
        sha256="a" * 64,
        is_split_member=False,
        split_group_id=None,
        device_serial="DEV1",
        harvested_at=None,
        storage_root_id="2",
        data_root=str(tmp_path / "missing-old-root"),
        local_rel_path="device_apks/DEV1/runs/OLD/com.example.old/base.apk",
        recorded_abs_path=str(tmp_path / "missing-old-root" / "device_apks/DEV1/runs/OLD/com.example.old/base.apk"),
        recorded_root_exists=False,
        recorded_path_exists=False,
        canonical_rel_path="store/apk/sha256/aa/" + "a" * 64 + ".apk",
        canonical_abs_path=str(root / "store" / "apk" / "sha256" / "aa" / ("a" * 64 + ".apk")),
        canonical_exists=False,
        status=storage_pressure.STATUS_HISTORICAL_IDENTITY_ONLY,
    )

    audit = storage_pressure.build_storage_pressure_audit(root=root, db_identities=[historical])
    assert audit["truths"]["identity_known_in_db"]["apk_artifact_rows"] == 1
    assert audit["truths"]["session_copy_bytes_present"]["session_regular_apk_files"] == 0
    assert audit["truths"]["historical_provenance_only"]["rows"] == 1
