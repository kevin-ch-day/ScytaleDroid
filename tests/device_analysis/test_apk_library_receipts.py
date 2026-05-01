from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.StaticAnalysis.core import repository


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

    artifacts = repository._artifacts_from_receipt(receipt_path, payload)

    assert len(artifacts) == 1
    assert artifacts[0].metadata["device_serial"] == "ZY22JK89DR"
