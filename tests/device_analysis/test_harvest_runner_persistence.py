from __future__ import annotations

from pathlib import Path

import pytest

from tests.device_analysis._harvest_runner_support import (
    isolate_storage_contract,
    make_artifact_plan,
    make_inventory_row,
    make_package_plan,
    patch_runner_common,
)


pytestmark = [pytest.mark.unit]


@pytest.fixture(autouse=True)
def _isolate_storage_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_storage_contract(tmp_path, monkeypatch)


def test_execute_harvest_keeps_db_repo_available_for_package_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_func.harvest import apk_repository
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner

    calls: list[tuple[object, ...]] = []

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=True)
    monkeypatch.setattr(
        runner,
        "normalise_local_path",
        lambda dest_path: f"SERIAL123/20260328/com.example.app/{dest_path.name}",
    )

    def _fake_pull(**kwargs):
        dest_path = kwargs["dest_path"]
        dest_path.write_bytes(b"apk-bytes")
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    monkeypatch.setattr(apk_repository, "ensure_storage_root", lambda host_name, data_root, *, context=None: 7)

    def _ensure_app_definition(package_name, app_name=None, *, profile_key=None, context=None):
        del app_name, context
        calls.append(("app_definition", package_name, profile_key))
        return 11

    monkeypatch.setattr(apk_repository, "ensure_app_definition", _ensure_app_definition)

    def _upsert_apk_record(record, *, context=None):
        del context
        calls.append(("apk_record", record.package_name, record.sha256, record.signer_fingerprint))
        return 23

    monkeypatch.setattr(apk_repository, "upsert_apk_record", _upsert_apk_record)
    monkeypatch.setattr(
        apk_repository,
        "upsert_artifact_path",
        lambda apk_id, *, storage_root_id, local_rel_path, context=None: calls.append(
            ("artifact_path", apk_id, storage_root_id, local_rel_path)
        ),
    )
    monkeypatch.setattr(
        apk_repository,
        "upsert_source_path",
        lambda apk_id, source_path, *, context=None: calls.append(("source_path", apk_id, source_path)),
    )

    inventory = make_inventory_row(
        package_name="com.example.app",
        app_label="Example App",
        primary_path="/data/app/com.example.app/base.apk",
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.app/base.apk"],
        raw={"extras": {"signer_cert_digest": "a" * 64}},
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.app/base.apk",
                artifact="base",
                file_name="com_example_app_1__base.apk",
                is_split_member=False,
            )
        ],
        total_paths=1,
    )

    results = runner.execute_harvest(
        serial="SERIAL123",
        adb_path="adb",
        dest_root=tmp_path / "SERIAL123" / "20260328",
        session_stamp="20260328",
        plans=[plan],
        config=object(),
        pull_mode="inventory",
    )

    assert len(results) == 1
    assert results[0].skipped == []
    assert results[0].errors == []
    assert len(results[0].ok) == 1
    assert results[0].ok[0].apk_id == 23
    assert results[0].capture_status == "clean"
    assert results[0].persistence_status == "mirrored"
    assert results[0].research_status == "pending_audit"
    assert results[0].ok[0].canonical_store_path == (
        f"data/store/apk/sha256/{results[0].ok[0].sha256[:2]}/{results[0].ok[0].sha256}.apk"
    )
    assert results[0].package_manifest_path is not None
    assert results[0].package_manifest_path.exists()
    receipt_path = Path("data") / "receipts" / "harvest" / "20260328" / "com.example.app.json"
    assert receipt_path.exists()
    payload = receipt_path.read_text(encoding="utf-8")
    assert f'"signer_cert_digest": "{"a" * 64}"' in payload
    assert '"signer_set_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' in payload
    assert '"split_membership_hash":' in payload
    assert calls == [
        ("app_definition", "com.example.app", "TEST_PROFILE"),
        ("apk_record", "com.example.app", results[0].ok[0].sha256, "a" * 64),
        ("artifact_path", 23, 7, "SERIAL123/20260328/com.example.app/com_example_app_1__base.apk"),
        ("source_path", 23, "/data/app/com.example.app/base.apk"),
    ]


def test_execute_harvest_preserves_capture_when_db_mirror_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_func.harvest import apk_repository
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=True)

    def _fake_pull(**kwargs):
        dest_path = kwargs["dest_path"]
        dest_path.write_bytes(b"apk-bytes")
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    monkeypatch.setattr(apk_repository, "ensure_storage_root", lambda *args, **kwargs: 7)
    monkeypatch.setattr(apk_repository, "ensure_app_definition", lambda *args, **kwargs: 11)
    monkeypatch.setattr(apk_repository, "upsert_apk_record", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("db write failed")))

    inventory = make_inventory_row(
        package_name="com.example.dbfail",
        app_label="DB Fail",
        primary_path="/data/app/com.example.dbfail/base.apk",
        apk_paths=["/data/app/com.example.dbfail/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.dbfail/base.apk",
                artifact="base",
                file_name="com_example_dbfail_1__base.apk",
            )
        ],
        total_paths=1,
    )

    results = runner.execute_harvest(
        serial="SERIAL123",
        adb_path="adb",
        dest_root=tmp_path / "SERIAL123" / "20260328",
        session_stamp="20260328",
        plans=[plan],
        config=object(),
        pull_mode="inventory",
    )

    assert len(results) == 1
    result = results[0]
    assert result.errors == []
    assert len(result.ok) == 1
    assert result.capture_status == "clean"
    assert result.persistence_status == "mirror_failed"
    assert result.research_status == "pending_audit"
    assert "apk_record_failed" in result.mirror_failure_reasons
    assert "apk_record_failed" in result.skipped
    assert result.package_manifest_path is not None
    payload = result.package_manifest_path.read_text(encoding="utf-8")
    assert '"persistence_status": "mirror_failed"' in payload
    assert '"capture_status": "clean"' in payload


def test_execute_harvest_records_blocked_package_manifest_and_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, with_storage_root=False)

    inventory = make_inventory_row(
        package_name="com.example.blocked",
        app_label="Blocked App",
        primary_path="/system/app/Blocked/Blocked.apk",
        apk_paths=["/system/app/Blocked/Blocked.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[],
        total_paths=1,
        policy_filtered_count=1,
        policy_filtered_reason="non_root_paths",
        skip_reason="policy_non_root",
    )

    results = runner.execute_harvest(
        serial="SERIAL123",
        adb_path="adb",
        dest_root=tmp_path / "SERIAL123" / "20260328",
        session_stamp="20260328",
        plans=[plan],
        config=object(),
        pull_mode="inventory",
        snapshot_id=26,
        snapshot_captured_at="2026-04-16T04:31:10Z",
    )

    assert len(results) == 1
    result = results[0]
    assert result.preflight_reason == "policy_non_root"
    assert result.skipped == ["policy_non_root"]
    assert result.capture_status == "failed"
    assert result.persistence_status == "not_requested"
    assert result.research_status == "ineligible"
    assert result.package_manifest_path is not None
    assert result.package_manifest_path.exists()

    payload = result.package_manifest_path.read_text(encoding="utf-8")
    assert '"preflight_reason": "policy_non_root"' in payload
    assert '"snapshot_id": 26' in payload
    assert '"primary_path": "/system/app/Blocked/Blocked.apk"' in payload
    assert '"policy_filtered_count": 1' in payload
    assert '"policy_filtered_reason": "non_root_paths"' in payload
    assert '"capture_status": "failed"' in payload
    assert '"research_status": "ineligible"' in payload

    receipt_path = Path("data") / "receipts" / "harvest" / "20260328" / "com.example.blocked.json"
    assert receipt_path.exists()
