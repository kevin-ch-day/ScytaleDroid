from __future__ import annotations

import json
from pathlib import Path

from scripts.db.backfill_apk_sets_from_receipts import (
    artifact_set_hash_v1,
    collect_receipt_sets,
)


def test_artifact_set_hash_v1_matches_static_identity_list_payload() -> None:
    assert artifact_set_hash_v1(["b" * 64, "a" * 64]) == (
        "f5e608884dc64246cb6411c2d00a2726de7ce9cbdd32903d546a0df3f806dd00"
    )


def test_collect_receipt_sets_requires_observed_hashes_and_base(tmp_path: Path) -> None:
    root = tmp_path / "data" / "receipts" / "harvest" / "session-a"
    root.mkdir(parents=True)
    receipt = root / "com.example.json"
    receipt.write_text(
        json.dumps(
            {
                "comparison": {
                    "planned_artifact_count": 2,
                    "observed_artifact_count": 2,
                },
                "execution": {
                    "observed_artifacts": [
                        {
                            "is_base": True,
                            "split_label": "base",
                            "sha256": "b" * 64,
                            "pull_outcome": "written",
                        },
                        {
                            "is_base": False,
                            "split_label": "split_config.xhdpi",
                            "sha256": "a" * 64,
                            "pull_outcome": "written",
                        },
                    ]
                },
                "generated_at_utc": "2026-05-13T03:28:22.254974Z",
                "package": {
                    "device_serial": "SERIAL1",
                    "package_name": "com.example",
                    "session_label": "session-a",
                    "snapshot_id": 42,
                    "version_code": "7",
                    "version_name": "1.2.3",
                },
                "status": {"capture_status": "clean"},
            }
        ),
        encoding="utf-8",
    )

    sets, skipped = collect_receipt_sets(root.parent, limit=0)

    assert skipped["missing_hash"] == 0
    assert len(sets) == 1
    item = sets[0]
    assert item.package_name == "com.example"
    assert item.base_sha256 == "b" * 64
    assert item.completeness_state == "complete"
    assert item.artifact_set_hash == artifact_set_hash_v1(["b" * 64, "a" * 64])
    assert [member.split_name for member in item.members] == ["base", "split_config.xhdpi"]
