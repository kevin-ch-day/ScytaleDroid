from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.DeviceAnalysis.harvest.models import PullResult
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


def test_execute_harvest_library_hit_skips_adb_pull(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.services import apk_library_service, artifact_store

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=False)

    calls: list[str] = []

    def _fake_pull(**kwargs):
        calls.append(kwargs["source_path"])
        raise AssertionError("adb pull should not run for an APK library hit")

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    digest = "c" * 64
    canonical = artifact_store.canonical_apk_path(digest)
    canonical.parent.mkdir(parents=True, exist_ok=True)
    canonical.write_bytes(b"known-apk")
    canonical_rel = artifact_store.repo_relative_path(canonical)
    inventory = make_inventory_row(
        package_name="com.example.known",
        app_label="Known App",
        primary_path="/data/app/com.example.known/base.apk",
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.known/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.known/base.apk",
                artifact="base",
                file_name="com_example_known_1__base.apk",
            )
        ],
    )
    seed = PullResult(plan=plan)
    seed.ok.append(
        runner.ArtifactResult(
            file_name="com_example_known_1__base.apk",
            apk_id=None,
            dest_path=canonical,
            source_path="/data/app/com.example.known/base.apk",
            sha256=digest,
            file_size=canonical.stat().st_size,
            artifact_label="base",
            is_base=True,
            canonical_store_path=canonical_rel,
        )
    )
    assert apk_library_service.register_result(seed, serial="SERIAL123", session_stamp="seed") is not None

    results = runner.execute_harvest(
        serial="SERIAL123",
        adb_path="adb",
        dest_root=tmp_path / "SERIAL123" / "20260329",
        session_stamp="20260329",
        plans=[plan],
        config=object(),
        pull_mode="inventory",
    )

    assert calls == []
    assert len(results) == 1
    result = results[0]
    assert result.capture_status == "clean"
    assert result.research_status == "pending_audit"
    assert result.ok[0].status == "library_hit"
    assert result.ok[0].dest_path == canonical.resolve()
    assert "apk_library_hit" in result.skipped
    assert result.package_manifest_path is not None
    payload = result.package_manifest_path.read_text(encoding="utf-8")
    assert '"pull_outcome": "library_hit"' in payload
    assert '"apk_library_hit": true' in payload
    assert not (result.package_manifest_path.parent / "com_example_known_1__base.apk").exists()


def test_execute_harvest_does_not_library_hit_known_content_variant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.services import apk_library_service, artifact_store

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=False)

    calls: list[str] = []
    events: list[dict[str, object]] = []

    class CaptureLogger:
        extra: dict[str, object] = {}

        def info(self, message, *, extra=None):
            del message
            events.append(extra or {})

        def warning(self, message, *, extra=None):
            del message
            events.append(extra or {})

        def error(self, message, *, extra=None):
            del message
            events.append(extra or {})

    def _fake_pull(**kwargs):
        calls.append(kwargs["source_path"])
        kwargs["dest_path"].write_bytes(b"fresh-apk-variant")
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    inventory = make_inventory_row(
        package_name="com.example.variant",
        app_label="Variant App",
        primary_path="/data/app/com.example.variant/base.apk",
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.variant/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.variant/base.apk",
                artifact="base",
                file_name="com_example_variant_1__base.apk",
            )
        ],
    )
    first_digest = "d" * 64
    second_digest = "e" * 64
    first_canonical = artifact_store.canonical_apk_path(first_digest)
    first_canonical.parent.mkdir(parents=True, exist_ok=True)
    first_canonical.write_bytes(b"known-apk")
    second_canonical = artifact_store.canonical_apk_path(second_digest)
    second_canonical.parent.mkdir(parents=True, exist_ok=True)
    second_canonical.write_bytes(b"other-known-apk")
    seed = PullResult(plan=plan)
    seed.ok.append(
        runner.ArtifactResult(
            file_name="com_example_variant_1__base.apk",
            apk_id=None,
            dest_path=first_canonical,
            source_path="/data/app/com.example.variant/base.apk",
            sha256=first_digest,
            file_size=first_canonical.stat().st_size,
            artifact_label="base",
            is_base=True,
            canonical_store_path=artifact_store.repo_relative_path(first_canonical),
        )
    )
    variant = PullResult(plan=plan)
    variant.ok.append(
        runner.ArtifactResult(
            file_name="com_example_variant_1__base.apk",
            apk_id=None,
            dest_path=second_canonical,
            source_path="/data/app/com.example.variant/base.apk",
            sha256=second_digest,
            file_size=second_canonical.stat().st_size,
            artifact_label="base",
            is_base=True,
            canonical_store_path=artifact_store.repo_relative_path(second_canonical),
        )
    )
    assert apk_library_service.register_result(seed, serial="SERIAL123", session_stamp="seed") is not None
    assert apk_library_service.register_result(variant, serial="SERIAL123", session_stamp="variant") is not None

    results = runner.execute_harvest(
        serial="SERIAL123",
        adb_path="adb",
        dest_root=tmp_path / "SERIAL123" / "20260330",
        session_stamp="20260330",
        plans=[plan],
        config=object(),
        pull_mode="inventory",
        harvest_logger=CaptureLogger(),
    )

    assert calls == ["/data/app/com.example.variant/base.apk"]
    assert len(results) == 1
    result = results[0]
    assert "apk_library_hit" not in result.skipped
    assert result.ok[0].status != "library_hit"
    assert result.package_manifest_path is not None
    payload = result.package_manifest_path.read_text(encoding="utf-8")
    assert '"apk_library_hit": true' not in payload
    assert any(
        event.get("event") == "harvest.package.apk_library_content_variant_pull_required"
        and event.get("reason") == "content_variant_requires_fresh_pull"
        for event in events
    )


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
