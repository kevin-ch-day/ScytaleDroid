from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.DeviceAnalysis.services.legacy_harvest_migration import (
    migrate_legacy_harvest_tree,
)


def test_migrate_legacy_harvest_tree_writes_store_and_receipt(monkeypatch, tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    legacy_pkg_dir = data_root / "device_apks" / "SERIAL123" / "20260328" / "com.example.app"
    legacy_pkg_dir.mkdir(parents=True)
    apk_path = legacy_pkg_dir / "com_example_app_101__base.apk"
    apk_path.write_bytes(b"apk")
    sha256 = "a" * 64
    sidecar_path = apk_path.with_suffix(".apk.meta.json")
    sidecar_path.write_text(
        json.dumps(
            {
                "package_name": "com.example.app",
                "app_label": "Example",
                "artifact": "base",
                "artifact_kind": "apk",
                "captured_at": "2026-03-28T10:00:00Z",
                "device_serial": "SERIAL123",
                "file_name": apk_path.name,
                "file_size": len(b"apk"),
                "installer": "com.android.vending",
                "is_split_member": False,
                "local_path": "device_apks/SERIAL123/20260328/com.example.app/com_example_app_101__base.apk",
                "md5": "b" * 32,
                "package_name": "com.example.app",
                "session_stamp": "20260328-rda-full",
                "sha1": "c" * 40,
                "sha256": sha256,
                "source_path": "/data/app/example/base.apk",
                "version_code": "101",
                "version_name": "1.0.1",
            }
        ),
        encoding="utf-8",
    )
    manifest_path = legacy_pkg_dir / "harvest_package_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "harvest_package_manifest_v1",
                "generated_at_utc": "2026-03-28T10:00:00Z",
                "execution_state": "completed",
                "package": {
                    "package_name": "com.example.app",
                    "app_label": "Example",
                    "version_name": "1.0.1",
                    "version_code": "101",
                    "device_serial": "SERIAL123",
                    "session_label": "20260328-rda-full",
                },
                "inventory": {
                    "installer": "com.android.vending",
                    "category": "Social media",
                    "profile_key": "RESEARCH_DATASET_ALPHA",
                    "profile_name": "Research Dataset Alpha",
                },
                "planning": {"expected_artifacts": []},
                "execution": {
                    "observed_artifacts": [
                        {
                            "split_label": "base",
                            "file_name": apk_path.name,
                            "is_base": True,
                            "local_artifact_path": "device_apks/SERIAL123/20260328/com.example.app/com_example_app_101__base.apk",
                            "observed_source_path": "/data/app/example/base.apk",
                            "sha256": sha256,
                            "file_size": len(b"apk"),
                            "pull_outcome": "written",
                        }
                    ],
                    "errors": [],
                    "runtime_skips": [],
                    "mirror_failure_reasons": [],
                    "drift_reasons": [],
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

    monkeypatch.setattr(app_config, "DATA_DIR", str(data_root))
    summary = migrate_legacy_harvest_tree()

    assert summary.manifests_scanned == 1
    assert summary.receipts_written == 1
    canonical_apk = data_root / "store" / "apk" / "sha256" / "aa" / f"{sha256}.apk"
    assert canonical_apk.exists()
    receipt_path = data_root / "receipts" / "harvest" / "20260328-rda-full" / "com.example.app.json"
    assert receipt_path.exists()
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    observed = receipt_payload["execution"]["observed_artifacts"][0]
    assert observed["canonical_store_path"] == artifact_store.repo_relative_path(canonical_apk)
    canonical_sidecar = canonical_apk.with_suffix(".apk.meta.json")
    assert canonical_sidecar.exists()
