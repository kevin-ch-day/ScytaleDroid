from __future__ import annotations

import json
from pathlib import Path

import pytest
from scytaledroid.Database.db_func.harvest import apk_repository, install_sets
from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.DeviceAnalysis.harvest import runner
from scytaledroid.DeviceAnalysis.harvest.models import CANONICAL_MATERIALIZATION_FAILED
from scytaledroid.DeviceAnalysis.services import artifact_store
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


def _write_pulled_apk(dest_path: Path, payload: bytes = b"apk-bytes") -> None:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_bytes(payload)


def _patch_success_db(monkeypatch: pytest.MonkeyPatch, calls: list[tuple[object, ...]]) -> None:
    monkeypatch.setattr(apk_repository, "ensure_storage_root", lambda *args, **kwargs: 7)
    monkeypatch.setattr(apk_repository, "ensure_app_definition", lambda *args, **kwargs: 11)

    def _upsert_apk_record(record, *, context=None):
        del context
        calls.append(("apk_record", record.package_name, record.sha256))
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
        lambda apk_id, source_path, *, context=None: calls.append(
            ("source_path", apk_id, source_path)
        ),
    )
    monkeypatch.setattr(
        install_sets,
        "upsert_install_set",
        lambda record: calls.append(("install_set", record.package_name, record.status)) or 99,
    )


def test_materialization_success_allows_clean_research_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    patch_runner_common(
        monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=True
    )
    _patch_success_db(monkeypatch, calls)

    def _fake_pull(**kwargs):
        _write_pulled_apk(kwargs["dest_path"])
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    inventory = make_inventory_row(
        package_name="com.example.ok",
        app_label="OK",
        apk_paths=["/data/app/com.example.ok/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.ok/base.apk",
                artifact="base",
                file_name="com_example_ok_1__base.apk",
            )
        ],
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

    result = results[0]
    assert result.errors == []
    assert result.capture_status == "clean"
    assert result.persistence_status == "mirrored"
    assert result.research_status == "pending_audit"
    assert result.ok[0].canonical_store_path
    assert (tmp_path / result.ok[0].canonical_store_path).exists()
    assert any(call[0] == "apk_record" for call in calls)
    assert any(call[0] == "install_set" for call in calls)


def test_materialization_exception_blocks_clean_mirror_and_research(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    events: list[dict[str, object]] = []
    patch_runner_common(
        monkeypatch,
        runner=runner,
        diagnostics=diagnostics,
        tmp_path=tmp_path,
        write_db=True,
        write_meta=True,
    )
    _patch_success_db(monkeypatch, calls)

    def _fake_pull(**kwargs):
        _write_pulled_apk(kwargs["dest_path"], b"session-only-apk")
        return True

    def _fail_materialize(path, *, sha256_digest, suffix=".apk", move=False):
        del path, sha256_digest, suffix, move
        raise OSError("canonical store write failed")

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

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    monkeypatch.setattr(artifact_store, "materialize_apk", _fail_materialize)

    inventory = make_inventory_row(
        package_name="com.example.failstore",
        app_label="Fail Store",
        apk_paths=["/data/app/com.example.failstore/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.failstore/base.apk",
                artifact="base",
                file_name="com_example_failstore_1__base.apk",
            )
        ],
    )

    results = runner.execute_harvest(
        serial="SERIAL123",
        adb_path="adb",
        dest_root=tmp_path / "SERIAL123" / "20260328",
        session_stamp="20260328",
        plans=[plan],
        config=object(),
        pull_mode="inventory",
        harvest_logger=CaptureLogger(),
    )

    result = results[0]
    session_copy = (
        tmp_path / "SERIAL123" / "20260328" / "Fail_Store" / "com_example_failstore_1__base.apk"
    )
    if not session_copy.exists():
        session_copy = next(tmp_path.rglob("com_example_failstore_1__base.apk"))
    assert session_copy.exists()
    assert session_copy.read_bytes() == b"session-only-apk"
    assert result.ok[0].status == CANONICAL_MATERIALIZATION_FAILED
    assert result.ok[0].canonical_store_path is None
    assert result.ok[0].sha256
    assert any(error.reason == CANONICAL_MATERIALIZATION_FAILED for error in result.errors)
    assert result.capture_status != "clean"
    assert result.persistence_status == "mirror_failed"
    assert result.research_status == "ineligible"
    assert not any(call[0] == "apk_record" for call in calls)
    assert not any(call[0] == "install_set" for call in calls)
    sidecar = session_copy.with_suffix(session_copy.suffix + ".meta.json")
    assert sidecar.exists()
    sidecar_payload = json.loads(sidecar.read_text(encoding="utf-8"))
    assert sidecar_payload["canonical_store_path"] is None
    assert sidecar_payload["canonical_materialization_status"] == "failed"
    assert sidecar_payload["canonical_materialization_error"]
    receipt = json.loads(result.package_manifest_path.read_text(encoding="utf-8"))
    assert receipt["status"]["capture_status"] != "clean"
    assert receipt["status"]["persistence_status"] == "mirror_failed"
    assert receipt["status"]["research_status"] == "ineligible"
    assert receipt["status"]["canonical_durability_status"] == "failed"
    assert receipt["comparison"]["acquisition_complete"] is True
    assert receipt["execution"]["errors"][0]["reason"] == CANONICAL_MATERIALIZATION_FAILED
    assert receipt["execution"]["errors"][0]["sha256"]
    assert receipt["execution"]["errors"][0]["session_copy"]
    assert any(
        event.get("event") == "harvest.artifact.canonical_materialization_failed"
        for event in events
    )
    assert "harvest.artifact.saved" not in {event.get("event") for event in events}


def test_existing_canonical_destination_reused_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    patch_runner_common(
        monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=True
    )
    _patch_success_db(monkeypatch, calls)

    digest = None

    def _fake_pull(**kwargs):
        payload = b"already-known-apk"
        _write_pulled_apk(kwargs["dest_path"], payload)
        nonlocal digest
        from hashlib import sha256

        digest = sha256(payload).hexdigest()
        stored = artifact_store.canonical_apk_path(digest)
        stored.parent.mkdir(parents=True, exist_ok=True)
        stored.write_bytes(payload)
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    inventory = make_inventory_row(
        package_name="com.example.reuse",
        app_label="Reuse",
        apk_paths=["/data/app/com.example.reuse/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.reuse/base.apk",
                artifact="base",
                file_name="com_example_reuse_1__base.apk",
            )
        ],
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

    result = results[0]
    assert result.capture_status == "clean"
    assert result.research_status == "pending_audit"
    assert result.ok[0].canonical_store_path == (f"data/store/apk/sha256/{digest[:2]}/{digest}.apk")


def test_broken_existing_canonical_destination_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    patch_runner_common(
        monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=True
    )
    _patch_success_db(monkeypatch, calls)

    def _fake_pull(**kwargs):
        payload = b"fresh-session-apk"
        _write_pulled_apk(kwargs["dest_path"], payload)
        from hashlib import sha256

        digest = sha256(payload).hexdigest()
        stored = artifact_store.canonical_apk_path(digest)
        stored.parent.mkdir(parents=True, exist_ok=True)
        stored.symlink_to(tmp_path / "missing-cold" / f"{digest}.apk")
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    inventory = make_inventory_row(
        package_name="com.example.broken",
        app_label="Broken",
        apk_paths=["/data/app/com.example.broken/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.broken/base.apk",
                artifact="base",
                file_name="com_example_broken_1__base.apk",
            )
        ],
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

    result = results[0]
    assert result.research_status == "ineligible"
    assert result.capture_status != "clean"
    assert result.ok[0].canonical_store_path is None
    assert any(error.reason == CANONICAL_MATERIALIZATION_FAILED for error in result.errors)
    assert not any(call[0] == "apk_record" for call in calls)
    session_copy = next(tmp_path.rglob("com_example_broken_1__base.apk"))
    assert session_copy.exists()
    assert not session_copy.is_symlink()


def test_split_set_partial_materialization_is_not_research_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    patch_runner_common(
        monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=True
    )
    _patch_success_db(monkeypatch, calls)
    original_materialize = artifact_store.materialize_apk

    def _fake_pull(**kwargs):
        _write_pulled_apk(kwargs["dest_path"], kwargs["dest_path"].name.encode())
        return True

    def _materialize(path, *, sha256_digest, suffix=".apk", move=False):
        if path.name.endswith("split_config.xxhdpi.apk"):
            raise OSError("no space left on device")
        return original_materialize(path, sha256_digest=sha256_digest, suffix=suffix, move=move)

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    monkeypatch.setattr(artifact_store, "materialize_apk", _materialize)

    paths = [
        "/data/app/com.example.split/base.apk",
        "/data/app/com.example.split/split_config.en.apk",
        "/data/app/com.example.split/split_config.xxhdpi.apk",
        "/data/app/com.example.split/split_config.arm64.apk",
    ]
    inventory = make_inventory_row(
        package_name="com.example.split",
        app_label="Split App",
        primary_path=paths[0],
        apk_paths=paths,
        raw={
            "package_manager_split_names": ["base", "config.en", "config.xxhdpi", "config.arm64"],
            "package_manager_split_count": 4,
        },
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(source_path=paths[0], artifact="base", file_name="base.apk"),
            make_artifact_plan(
                source_path=paths[1],
                artifact="config.en",
                file_name="split_config.en.apk",
                is_split_member=True,
            ),
            make_artifact_plan(
                source_path=paths[2],
                artifact="config.xxhdpi",
                file_name="split_config.xxhdpi.apk",
                is_split_member=True,
            ),
            make_artifact_plan(
                source_path=paths[3],
                artifact="config.arm64",
                file_name="split_config.arm64.apk",
                is_split_member=True,
            ),
        ],
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

    result = results[0]
    assert len(result.ok) == 4
    failed = [
        artifact for artifact in result.ok if artifact.status == CANONICAL_MATERIALIZATION_FAILED
    ]
    assert len(failed) == 1
    assert failed[0].file_name == "split_config.xxhdpi.apk"
    assert result.capture_status == "partial"
    assert result.persistence_status == "mirror_failed"
    assert result.research_status == "ineligible"
    assert not any(call[0] == "install_set" for call in calls)
    assert result.comparison["canonical_store_complete"] is False
    assert result.comparison["acquisition_complete"] is True


def test_db_mirror_failure_after_canonical_success_stays_distinct(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_runner_common(
        monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=True
    )

    def _fake_pull(**kwargs):
        _write_pulled_apk(kwargs["dest_path"])
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    monkeypatch.setattr(apk_repository, "ensure_storage_root", lambda *args, **kwargs: 7)
    monkeypatch.setattr(apk_repository, "ensure_app_definition", lambda *args, **kwargs: 11)
    monkeypatch.setattr(
        apk_repository,
        "upsert_apk_record",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("db write failed")),
    )

    inventory = make_inventory_row(
        package_name="com.example.dbfail",
        app_label="DB Fail",
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

    result = results[0]
    assert result.ok[0].canonical_store_path
    assert (tmp_path / result.ok[0].canonical_store_path).exists()
    assert result.capture_status == "clean"
    assert result.persistence_status == "mirror_failed"
    assert result.research_status == "pending_audit"
    assert "apk_record_failed" in result.mirror_failure_reasons
    assert CANONICAL_MATERIALIZATION_FAILED not in result.mirror_failure_reasons


def test_valid_cold_symlink_counts_as_durable_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    patch_runner_common(
        monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=True
    )
    _patch_success_db(monkeypatch, calls)
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    monkeypatch.setattr(artifact_store, "EXTERNAL_APK_STORE_MOUNT_ROOTS", (external_mount,))
    monkeypatch.setattr(
        artifact_store.os.path, "ismount", lambda path: Path(path) == external_mount
    )

    def _fake_pull(**kwargs):
        payload = b"cold-apk-bytes"
        _write_pulled_apk(kwargs["dest_path"], payload)
        from hashlib import sha256

        digest = sha256(payload).hexdigest()
        cold_target = (
            external_mount
            / "cold"
            / "data"
            / "store"
            / "apk"
            / "sha256"
            / digest[:2]
            / f"{digest}.apk"
        )
        cold_target.parent.mkdir(parents=True, exist_ok=True)
        cold_target.write_bytes(payload)
        local_blob = artifact_store.canonical_apk_path(digest)
        local_blob.parent.mkdir(parents=True, exist_ok=True)
        if local_blob.exists() or local_blob.is_symlink():
            local_blob.unlink()
        local_blob.symlink_to(cold_target)
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    inventory = make_inventory_row(
        package_name="com.example.cold",
        app_label="Cold",
        apk_paths=["/data/app/com.example.cold/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.cold/base.apk",
                artifact="base",
                file_name="com_example_cold_1__base.apk",
            )
        ],
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

    result = results[0]
    assert result.capture_status == "clean"
    assert result.research_status == "pending_audit"
    assert result.ok[0].canonical_store_path
    canonical = tmp_path / result.ok[0].canonical_store_path
    assert canonical.is_symlink()
    assert canonical.exists()


def test_broken_cold_symlink_is_not_durable_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    patch_runner_common(
        monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path, write_db=True
    )
    _patch_success_db(monkeypatch, calls)
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    monkeypatch.setattr(artifact_store, "EXTERNAL_APK_STORE_MOUNT_ROOTS", (external_mount,))
    monkeypatch.setattr(
        artifact_store.os.path, "ismount", lambda path: Path(path) == external_mount
    )

    def _fake_pull(**kwargs):
        payload = b"cold-missing-apk"
        _write_pulled_apk(kwargs["dest_path"], payload)
        from hashlib import sha256

        digest = sha256(payload).hexdigest()
        cold_target = (
            external_mount
            / "cold"
            / "data"
            / "store"
            / "apk"
            / "sha256"
            / digest[:2]
            / f"{digest}.apk"
        )
        local_blob = artifact_store.canonical_apk_path(digest)
        local_blob.parent.mkdir(parents=True, exist_ok=True)
        if local_blob.exists() or local_blob.is_symlink():
            local_blob.unlink()
        local_blob.symlink_to(cold_target)
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    inventory = make_inventory_row(
        package_name="com.example.coldbreak",
        app_label="Cold Break",
        apk_paths=["/data/app/com.example.coldbreak/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.coldbreak/base.apk",
                artifact="base",
                file_name="com_example_coldbreak_1__base.apk",
            )
        ],
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

    result = results[0]
    assert result.research_status == "ineligible"
    assert result.capture_status != "clean"
    assert result.persistence_status == "mirror_failed"
    assert not any(call[0] == "apk_record" for call in calls)
    session_copy = next(tmp_path.rglob("com_example_coldbreak_1__base.apk"))
    assert session_copy.exists()
