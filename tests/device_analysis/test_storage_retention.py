from __future__ import annotations

import csv
import json
from hashlib import sha256
from pathlib import Path

from scytaledroid.DeviceAnalysis.services import storage_retention


def _write_apk(path: Path, payload: bytes) -> tuple[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return sha256(payload).hexdigest(), len(payload)


def _write_harvest_receipt(
    path: Path,
    *,
    package_name: str,
    version_code: str,
    session_label: str,
    device_serial: str,
    relative_path: str,
    sha: str,
    size: int,
    pulled_at: str,
) -> None:
    payload = {
        "schema": "harvest_package_manifest_v1",
        "package": {
            "package_name": package_name,
            "version_code": version_code,
            "session_label": session_label,
            "device_serial": device_serial,
        },
        "execution": {
            "observed_artifacts": [
                {
                    "split_label": "base",
                    "file_name": Path(relative_path).name,
                    "local_artifact_path": relative_path,
                    "sha256": sha,
                    "file_size": size,
                    "pulled_at": pulled_at,
                }
            ]
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_build_retention_audit_detects_duplicate_payloads_across_sessions(tmp_path: Path) -> None:
    root = tmp_path / "data"
    rel_old = "store/apk/sha256/ab/ab-old.apk"
    rel_new = "store/apk/sha256/cd/cd-new.apk"
    sha, size = _write_apk(root / rel_old, b"same-payload")
    _write_apk(root / rel_new, b"same-payload")
    _write_harvest_receipt(
        root / "receipts" / "harvest" / "20260328" / "com.example.app.json",
        package_name="com.example.app",
        version_code="1",
        session_label="20260328",
        device_serial="DEV1",
        relative_path=rel_old,
        sha=sha,
        size=size,
        pulled_at="2026-03-28T12:00:00Z",
    )
    _write_harvest_receipt(
        root / "receipts" / "harvest" / "20260329" / "com.example.app.json",
        package_name="com.example.app",
        version_code="1",
        session_label="20260329",
        device_serial="DEV1",
        relative_path=rel_new,
        sha=sha,
        size=size,
        pulled_at="2026-03-29T12:00:00Z",
    )

    records, issues = storage_retention.scan_apk_storage(root)
    assert issues == []
    assert len(records) == 2

    audit = storage_retention.build_retention_audit(records, survivor_policy="oldest", issues=issues)
    assert audit["summary"]["duplicate_groups"] == 1
    assert audit["summary"]["duplicate_payloads"] == 1
    assert audit["summary"]["reclaimable_bytes"] == size

    group = audit["duplicate_groups"][0]
    assert group["retained"]["relative_path"] == rel_old
    assert group["candidates"][0]["relative_path"] == rel_new


def test_generate_retention_audit_includes_standalone_upload_sidecar(tmp_path: Path) -> None:
    root = tmp_path / "data"
    rel_path = "store/apk/sha256/ef/upload-1.apk"
    apk_path = root / rel_path
    sha, size = _write_apk(apk_path, b"uploaded-apk")
    sidecar = apk_path.with_suffix(apk_path.suffix + ".meta.json")
    sidecar.write_text(
        json.dumps(
            {
                "package_name": "com.example.upload",
                "version_code": "99",
                "local_path": rel_path,
                "sha256": sha,
                "file_size": size,
                "artifact": "base",
                "source_kind": "api_upload",
                "session_stamp": "upload-session",
                "device_serial": None,
                "captured_at": "2026-03-31T10:00:00Z",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    audit, json_path, csv_path = storage_retention.generate_retention_audit(
        root=root,
        out_dir=tmp_path / "audit",
        survivor_policy="oldest",
        stamp="20260331T120000Z",
    )

    assert audit["summary"]["records_scanned"] == 1
    assert audit["summary"]["duplicate_groups"] == 0
    assert json_path.exists()
    assert csv_path.exists()

    rows = list(csv.DictReader(csv_path.read_text(encoding="utf-8").splitlines()))
    assert rows == []
