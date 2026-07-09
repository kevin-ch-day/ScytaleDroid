from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.models import ArtifactResult, PullResult
from scytaledroid.DeviceAnalysis.services import apk_library_service, artifact_store
from tests.device_analysis._harvest_runner_support import (
    isolate_storage_contract,
    make_artifact_plan,
    make_inventory_row,
    make_package_plan,
)


pytestmark = [pytest.mark.unit]


@pytest.fixture(autouse=True)
def _isolate_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_storage_contract(tmp_path, monkeypatch)


def _plan(split: bool = False):
    apk_paths = ["/data/app/com.example.app/base.apk"]
    artifacts = [
        make_artifact_plan(
            source_path=apk_paths[0],
            artifact="base",
            file_name="com_example_app_1__base.apk",
            is_split_member=False,
        )
    ]
    if split:
        apk_paths.append("/data/app/com.example.app/split_config.en.apk")
        artifacts.append(
            make_artifact_plan(
                source_path=apk_paths[1],
                artifact="split_config.en",
                file_name="com_example_app_1__split_config.en.apk",
                is_split_member=True,
            )
        )
    inv = make_inventory_row(
        package_name="com.example.app",
        version_code="1",
        version_name="1.0",
        apk_paths=apk_paths,
        split_count=len(apk_paths),
    )
    return make_package_plan(inventory=inv, artifacts=artifacts)


def _stored_apk(digest: str, content: bytes = b"apk") -> str:
    path = artifact_store.canonical_apk_path(digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return artifact_store.repo_relative_path(path)


def _pull_result(plan, digest: str, canonical: str) -> PullResult:
    result = PullResult(plan=plan)
    result.ok.append(
        ArtifactResult(
            file_name=plan.artifacts[0].file_name,
            apk_id=None,
            dest_path=Path(canonical),
            source_path=plan.artifacts[0].source_path,
            sha256=digest,
            file_size=3,
            artifact_label=plan.artifacts[0].artifact,
            is_base=not plan.artifacts[0].is_split_member,
            canonical_store_path=canonical,
        )
    )
    return result


def test_register_result_creates_package_version_split_set_entry() -> None:
    plan = _plan()
    digest = "a" * 64
    canonical = _stored_apk(digest)
    result = _pull_result(plan, digest, canonical)

    entry = apk_library_service.register_result(result, serial="SER", session_stamp="run-1")

    assert entry is not None
    assert entry.manifest_path.exists()
    assert entry.artifacts[0].sha256 == digest
    assert (entry.entry_dir / "artifacts.csv").exists()
    assert (entry.entry_dir / "harvest_history.csv").exists()
    assert apk_library_service.find_entry_for_plan(plan) is not None


def test_register_result_indexes_same_planned_split_set_content_variant_without_overwrite() -> None:
    plan = _plan()
    first_digest = "a" * 64
    second_digest = "b" * 64
    first_canonical = _stored_apk(first_digest, b"first")
    second_canonical = _stored_apk(second_digest, b"second")

    first_entry = apk_library_service.register_result(_pull_result(plan, first_digest, first_canonical), serial="SER", session_stamp="run-1")
    second_entry = apk_library_service.register_result(_pull_result(plan, second_digest, second_canonical), serial="SER", session_stamp="run-2")

    assert first_entry is not None
    assert second_entry is not None
    assert second_entry.entry_dir == first_entry.entry_dir / "content_variants" / second_entry.split_set_hash
    payload = json.loads(first_entry.manifest_path.read_text(encoding="utf-8"))
    assert payload["split_set_hash"] == first_entry.split_set_hash
    assert payload["artifacts"][0]["sha256"] == first_digest
    variant_payload = json.loads(second_entry.manifest_path.read_text(encoding="utf-8"))
    assert variant_payload["entry_kind"] == "content_variant"
    assert variant_payload["artifacts"][0]["sha256"] == second_digest
    history = (first_entry.entry_dir / "harvest_history.csv").read_text(encoding="utf-8")
    assert first_entry.split_set_hash in history
    assert "content_variant_indexed" in history
    assert apk_library_service.find_entry_for_plan(plan) is None
    assert apk_library_service.content_variant_entry_for_plan(plan) == first_entry


def test_split_set_difference_creates_distinct_entry() -> None:
    base_plan = _plan(split=False)
    split_plan = _plan(split=True)

    assert apk_library_service.planned_split_set_hash_for_plan(base_plan) != apk_library_service.planned_split_set_hash_for_plan(split_plan)


def test_legacy_receipt_can_seed_library_entry_without_pull() -> None:
    plan = _plan()
    digest = "b" * 64
    canonical = _stored_apk(digest)
    receipt_dir = Path(app_config.DATA_DIR) / "receipts" / "harvest" / "run-legacy"
    receipt_dir.mkdir(parents=True)
    (receipt_dir / "com.example.app.json").write_text(
        json.dumps(
            {
                "package": {
                    "package_name": "com.example.app",
                    "version_code": "1",
                    "version_name": "1.0",
                    "device_serial": "SER",
                    "session_label": "run-legacy",
                },
                "execution": {
                    "observed_artifacts": [
                        {
                            "file_name": "com_example_app_1__base.apk",
                            "split_label": "base",
                            "is_base": True,
                            "sha256": digest,
                            "file_size": 3,
                            "canonical_store_path": canonical,
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    entry = apk_library_service.find_entry_for_plan(plan)

    assert entry is not None
    assert entry.source == "legacy_harvest_receipt"
    assert entry.artifacts[0].canonical_relpath == canonical


def test_register_legacy_receipt_reconstructs_plan_from_receipt() -> None:
    digest = "d" * 64
    canonical = _stored_apk(digest)
    receipt_dir = Path(app_config.DATA_DIR) / "receipts" / "harvest" / "run-reconstruct"
    receipt_dir.mkdir(parents=True)
    receipt = receipt_dir / "com.example.app.json"
    receipt.write_text(
        json.dumps(
            {
                "package": {
                    "app_label": "Example",
                    "package_name": "com.example.app",
                    "version_code": "1",
                    "version_name": "1.0",
                    "device_serial": "SER",
                    "session_label": "run-reconstruct",
                },
                "inventory": {
                    "apk_paths": ["/data/app/com.example.app/base.apk"],
                    "installer": "com.android.vending",
                    "primary_path": "/data/app/com.example.app/base.apk",
                    "split_count": 1,
                },
                "planning": {
                    "expected_artifacts": [
                        {
                            "file_name": "com_example_app_1__base.apk",
                            "is_base": True,
                            "planned_source_path": "/data/app/com.example.app/base.apk",
                            "split_label": "base",
                        }
                    ],
                    "total_paths": 1,
                },
                "execution": {
                    "observed_artifacts": [
                        {
                            "file_name": "com_example_app_1__base.apk",
                            "split_label": "base",
                            "is_base": True,
                            "sha256": digest,
                            "file_size": 3,
                            "canonical_store_path": canonical,
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    seedable, reason = apk_library_service.legacy_receipt_seedable(receipt)
    entry = apk_library_service.register_legacy_receipt(receipt)

    assert (seedable, reason) == (True, "seedable")
    assert entry is not None
    assert entry.package_name == "com.example.app"
    assert entry.version_code == "1"
    assert entry.artifacts[0].sha256 == digest
