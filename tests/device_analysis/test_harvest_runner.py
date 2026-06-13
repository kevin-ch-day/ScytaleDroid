from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.Config import app_config


@pytest.fixture(autouse=True)
def _isolate_storage_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")


class _FakeAdapter:
    extra: dict[str, object] = {}

    def info(self, *args, **kwargs) -> None:
        pass

    def warning(self, *args, **kwargs) -> None:
        pass

    def error(self, *args, **kwargs) -> None:
        pass


class _FakeRunLogger:
    def info(self, *args, **kwargs) -> None:
        pass


def test_execute_harvest_keeps_db_repo_available_for_package_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_func.harvest import apk_repository
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest.common import HarvestOptions
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactPlan, InventoryRow, PackagePlan
    from scytaledroid.DeviceAnalysis.harvest import runner

    calls: list[tuple[object, ...]] = []

    monkeypatch.setattr(
        runner,
        "load_options",
        lambda config, *, pull_mode: HarvestOptions(
            write_db=True,
            write_meta=False,
            pull_mode=pull_mode,
        ),
    )
    monkeypatch.setattr(diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(runner, "get_run_logger", lambda *args, **kwargs: _FakeRunLogger())
    monkeypatch.setattr(runner.log, "harvest_adapter", lambda *args, **kwargs: _FakeAdapter())
    monkeypatch.setattr(runner.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "info", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "error", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "resolve_storage_root", lambda: ("test-host", tmp_path.as_posix()))
    monkeypatch.setattr(
        runner,
        "normalise_local_path",
        lambda dest_path: f"SERIAL123/20260328/com.example.app/{dest_path.name}",
    )
    monkeypatch.setattr(runner, "_quiet_mode", lambda: True)
    monkeypatch.setattr(runner, "_compact_mode", lambda: True)

    def _fake_pull(**kwargs):
        dest_path = kwargs["dest_path"]
        dest_path.write_bytes(b"apk-bytes")
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    monkeypatch.setattr(
        apk_repository,
        "ensure_storage_root",
        lambda host_name, data_root, *, context=None: 7,
    )

    def _ensure_app_definition(package_name, app_name=None, *, profile_key=None, context=None):
        calls.append(("app_definition", package_name, profile_key))
        return 11

    monkeypatch.setattr(apk_repository, "ensure_app_definition", _ensure_app_definition)

    def _upsert_apk_record(record, *, context=None):
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

    inventory = InventoryRow(
        raw={},
        package_name="com.example.app",
        app_label="Example App",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.app/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.app/base.apk"],
        split_count=1,
    )
    plan = PackagePlan(
        inventory=inventory,
        artifacts=[
            ArtifactPlan(
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
    receipt_path = (
        Path("data")
        / "receipts"
        / "harvest"
        / "20260328"
        / "com.example.app.json"
    )
    assert receipt_path.exists()
    assert calls == [
        ("app_definition", "com.example.app", "TEST_PROFILE"),
        ("apk_record", "com.example.app", results[0].ok[0].sha256),
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
    from scytaledroid.DeviceAnalysis.harvest.common import HarvestOptions
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactPlan, InventoryRow, PackagePlan

    monkeypatch.setattr(
        runner,
        "load_options",
        lambda config, *, pull_mode: HarvestOptions(
            write_db=True,
            write_meta=False,
            pull_mode=pull_mode,
        ),
    )
    monkeypatch.setattr(diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(runner, "get_run_logger", lambda *args, **kwargs: _FakeRunLogger())
    monkeypatch.setattr(runner.log, "harvest_adapter", lambda *args, **kwargs: _FakeAdapter())
    monkeypatch.setattr(runner.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "info", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "error", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "resolve_storage_root", lambda: ("test-host", tmp_path.as_posix()))
    monkeypatch.setattr(runner, "_quiet_mode", lambda: True)
    monkeypatch.setattr(runner, "_compact_mode", lambda: True)

    def _fake_pull(**kwargs):
        dest_path = kwargs["dest_path"]
        dest_path.write_bytes(b"apk-bytes")
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)
    monkeypatch.setattr(apk_repository, "ensure_storage_root", lambda *args, **kwargs: 7)
    monkeypatch.setattr(apk_repository, "ensure_app_definition", lambda *args, **kwargs: 11)

    def _raise_db_write(*args, **kwargs):
        raise RuntimeError("db write failed")

    monkeypatch.setattr(apk_repository, "upsert_apk_record", _raise_db_write)

    inventory = InventoryRow(
        raw={},
        package_name="com.example.dbfail",
        app_label="DB Fail",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.dbfail/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.dbfail/base.apk"],
        split_count=1,
    )
    plan = PackagePlan(
        inventory=inventory,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.example.dbfail/base.apk",
                artifact="base",
                file_name="com_example_dbfail_1__base.apk",
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
    from scytaledroid.DeviceAnalysis.harvest.common import HarvestOptions
    from scytaledroid.DeviceAnalysis.harvest.models import InventoryRow, PackagePlan

    monkeypatch.setattr(
        runner,
        "load_options",
        lambda config, *, pull_mode: HarvestOptions(
            write_db=False,
            write_meta=False,
            pull_mode=pull_mode,
        ),
    )
    monkeypatch.setattr(diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(runner, "get_run_logger", lambda *args, **kwargs: _FakeRunLogger())
    monkeypatch.setattr(runner.log, "harvest_adapter", lambda *args, **kwargs: _FakeAdapter())
    monkeypatch.setattr(runner.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "info", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "error", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "_quiet_mode", lambda: True)
    monkeypatch.setattr(runner, "_compact_mode", lambda: True)

    inventory = InventoryRow(
        raw={},
        package_name="com.example.blocked",
        app_label="Blocked App",
        installer="com.android.vending",
        category=None,
        primary_path="/system/app/Blocked/Blocked.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=["/system/app/Blocked/Blocked.apk"],
        split_count=1,
    )
    plan = PackagePlan(
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

    receipt_path = (
        Path("data")
        / "receipts"
        / "harvest"
        / "20260328"
        / "com.example.blocked.json"
    )
    assert receipt_path.exists()


def test_execute_harvest_replans_stale_package_and_recovers_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.common import HarvestOptions
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError, ArtifactPlan, InventoryRow, PackagePlan

    monkeypatch.setattr(
        runner,
        "load_options",
        lambda config, *, pull_mode: HarvestOptions(
            write_db=False,
            write_meta=False,
            pull_mode=pull_mode,
        ),
    )
    monkeypatch.setattr(diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(runner, "get_run_logger", lambda *args, **kwargs: _FakeRunLogger())
    monkeypatch.setattr(runner.log, "harvest_adapter", lambda *args, **kwargs: _FakeAdapter())
    monkeypatch.setattr(runner.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "info", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "error", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "resolve_storage_root", lambda: ("test-host", tmp_path.as_posix()))
    monkeypatch.setattr(runner, "_quiet_mode", lambda: True)
    monkeypatch.setattr(runner, "_compact_mode", lambda: True)

    attempts = {"count": 0}

    def _fake_pull(**kwargs):
        dest_path = kwargs["dest_path"]
        attempts["count"] += 1
        if attempts["count"] == 1:
            return ArtifactError(source_path=kwargs["source_path"], reason="path_stale")
        dest_path.write_bytes(b"apk-bytes")
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    inventory = InventoryRow(
        raw={},
        package_name="com.example.stale",
        app_label="Stale App",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.stale/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.stale/base.apk"],
        split_count=1,
    )
    plan = PackagePlan(
        inventory=inventory,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.example.stale/base.apk",
                artifact="base",
                file_name="com_example_stale_1__base.apk",
                is_split_member=False,
            )
        ],
        total_paths=1,
    )
    monkeypatch.setattr(
        runner.package_refresh,
        "replan_package_after_stale_path",
        lambda **_kwargs: (plan, tuple()),
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
    assert attempts["count"] == 2
    assert result.capture_status == "clean"
    assert result.persistence_status == "not_requested"
    assert result.research_status == "pending_audit"
    assert result.errors == []
    assert result.stale_replan_required is True
    assert result.stale_replan_outcome == "path_stale_refreshed_and_retried"
    assert len(result.ok) == 1


def test_pull_and_record_marks_stale_path_as_retryable_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.common import DedupeTracker, HarvestOptions
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError, ArtifactPlan, InventoryRow, PackagePlan

    monkeypatch.setattr(
        runner,
        "adb_pull",
        lambda **kwargs: ArtifactError(source_path=kwargs["source_path"], reason="path_stale"),
    )

    printed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        runner.common,
        "print_artifact_status",
        lambda _label, _file_name, **kwargs: printed.append((kwargs["suffix"], kwargs["level"])),
    )

    emitted: list[tuple[str, str, dict[str, object | None]]] = []

    inventory = InventoryRow(
        raw={},
        package_name="com.example.retry",
        app_label="Retry App",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.retry/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.retry/base.apk"],
        split_count=1,
    )
    plan = PackagePlan(
        inventory=inventory,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.example.retry/base.apk",
                artifact="base",
                file_name="com_example_retry_1__base.apk",
                is_split_member=False,
            )
        ],
        total_paths=1,
    )

    artifact_result, skip_reason = runner._pull_and_record(
        serial="SERIAL123",
        adb_path="adb",
        package_dir=tmp_path,
        plan=plan,
        artifact=plan.artifacts[0],
        app_id=None,
        group_id=None,
        verbose=False,
        options=HarvestOptions(write_db=False, write_meta=False, pull_mode="inventory"),
        tracker=DedupeTracker(HarvestOptions(write_db=False, write_meta=False, pull_mode="inventory")),
        session_stamp="20260328",
        storage_root_id=None,
        artifact_index=1,
        artifact_total=1,
        verbose_output=False,
        base_context={},
        db_repo=None,
        emit=lambda level, event, extra, message=None: emitted.append((level, event, dict(extra or {}))),
        stats={},
        snapshot_id=None,
        snapshot_captured_at=None,
    )

    assert isinstance(artifact_result, ArtifactError)
    assert artifact_result.reason == "path_stale"
    assert skip_reason is None
    assert printed == [("path stale; replan required", "warn")]
    assert emitted == [
        (
            "warning",
            "harvest.artifact.retryable",
            {
                "package_name": "com.example.retry",
                "artifact_path": "/data/app/com.example.retry/base.apk",
                "file_name": "com_example_retry_1__base.apk",
                "error": "path_stale",
            },
        )
    ]


def test_execute_harvest_marks_package_drifted_after_partial_pull_replan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.common import HarvestOptions
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError, ArtifactPlan, InventoryRow, PackagePlan

    monkeypatch.setattr(
        runner,
        "load_options",
        lambda config, *, pull_mode: HarvestOptions(
            write_db=False,
            write_meta=False,
            pull_mode=pull_mode,
        ),
    )
    monkeypatch.setattr(diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(runner, "get_run_logger", lambda *args, **kwargs: _FakeRunLogger())
    monkeypatch.setattr(runner.log, "harvest_adapter", lambda *args, **kwargs: _FakeAdapter())
    monkeypatch.setattr(runner.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "info", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "error", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "resolve_storage_root", lambda: ("test-host", tmp_path.as_posix()))
    monkeypatch.setattr(runner, "_quiet_mode", lambda: True)
    monkeypatch.setattr(runner, "_compact_mode", lambda: True)

    def _fake_pull(**kwargs):
        dest_path = kwargs["dest_path"]
        if kwargs["source_path"].endswith("/base.apk"):
            dest_path.write_bytes(b"base-apk")
            return True
        return ArtifactError(source_path=kwargs["source_path"], reason="path_stale")

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    inventory = InventoryRow(
        raw={},
        package_name="com.example.drift",
        app_label="Drift App",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.drift/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=[
            "/data/app/com.example.drift/base.apk",
            "/data/app/com.example.drift/split_config.arm64_v8a.apk",
        ],
        split_count=2,
    )
    original_plan = PackagePlan(
        inventory=inventory,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.example.drift/base.apk",
                artifact="base",
                file_name="com_example_drift_1__base.apk",
                is_split_member=False,
            ),
            ArtifactPlan(
                source_path="/data/app/com.example.drift/split_config.arm64_v8a.apk",
                artifact="split_config.arm64_v8a",
                file_name="com_example_drift_1__split_config.arm64_v8a.apk",
                is_split_member=True,
            ),
        ],
        total_paths=2,
    )
    drifted_plan = PackagePlan(
        inventory=InventoryRow(
            raw={},
            package_name="com.example.drift",
            app_label="Drift App",
            installer="com.android.vending",
            category=None,
            primary_path="/data/app/com.example.drift/base.apk",
            profile_key="TEST_PROFILE",
            profile=None,
            version_name="1.1",
            version_code="2",
            apk_paths=[
                "/data/app/com.example.drift/base.apk",
                "/data/app/com.example.drift/split_config.xxhdpi.apk",
            ],
            split_count=2,
        ),
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.example.drift/base.apk",
                artifact="base",
                file_name="com_example_drift_2__base.apk",
                is_split_member=False,
            ),
            ArtifactPlan(
                source_path="/data/app/com.example.drift/split_config.xxhdpi.apk",
                artifact="split_config.xxhdpi",
                file_name="com_example_drift_2__split_config.xxhdpi.apk",
                is_split_member=True,
            ),
        ],
        total_paths=2,
    )
    monkeypatch.setattr(
        runner.package_refresh,
        "replan_package_after_stale_path",
        lambda **_kwargs: (drifted_plan, ("version_code_changed", "artifact_set_changed")),
    )

    results = runner.execute_harvest(
        serial="SERIAL123",
        adb_path="adb",
        dest_root=tmp_path / "SERIAL123" / "20260328",
        session_stamp="20260328",
        plans=[original_plan],
        config=object(),
        pull_mode="inventory",
    )

    assert len(results) == 1
    result = results[0]
    assert result.capture_status == "drifted"
    assert result.persistence_status == "not_requested"
    assert result.research_status == "ineligible"
    assert sorted(result.drift_reasons) == ["artifact_set_changed", "version_code_changed"]
    assert result.stale_replan_required is True
    assert result.stale_replan_outcome == "path_stale_package_updated_since_inventory"
    assert len(result.ok) == 1
    assert len(result.errors) == 1
    assert result.errors[0].reason == "package_drift_detected_after_partial_pull"
    assert result.package_manifest_path is not None
    payload = result.package_manifest_path.read_text(encoding="utf-8")
    assert '"capture_status": "drifted"' in payload
    assert '"drift_reasons": [' in payload


def test_execute_harvest_surfaces_refreshed_skip_reason_after_stale_path_replan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.common import HarvestOptions
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError, ArtifactPlan, InventoryRow, PackagePlan

    monkeypatch.setattr(
        runner,
        "load_options",
        lambda config, *, pull_mode: HarvestOptions(
            write_db=False,
            write_meta=False,
            pull_mode=pull_mode,
        ),
    )
    monkeypatch.setattr(diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(runner, "get_run_logger", lambda *args, **kwargs: _FakeRunLogger())
    monkeypatch.setattr(runner.log, "harvest_adapter", lambda *args, **kwargs: _FakeAdapter())
    monkeypatch.setattr(runner.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "info", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "error", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "resolve_storage_root", lambda: ("test-host", tmp_path.as_posix()))
    monkeypatch.setattr(runner, "_quiet_mode", lambda: True)
    monkeypatch.setattr(runner, "_compact_mode", lambda: True)
    monkeypatch.setattr(
        runner,
        "adb_pull",
        lambda **kwargs: ArtifactError(source_path=kwargs["source_path"], reason="path_stale"),
    )

    inventory = InventoryRow(
        raw={},
        package_name="com.example.reblocked",
        app_label="Reblocked App",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.reblocked/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.reblocked/base.apk"],
        split_count=1,
    )
    original_plan = PackagePlan(
        inventory=inventory,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.example.reblocked/base.apk",
                artifact="base",
                file_name="com_example_reblocked_1__base.apk",
                is_split_member=False,
            )
        ],
        total_paths=1,
    )
    refreshed_plan = PackagePlan(
        inventory=InventoryRow(
            raw={"path_fidelity": "bulk_base_only"},
            package_name="com.example.reblocked",
            app_label="Reblocked App",
            installer="com.android.vending",
            category=None,
            primary_path="/system/app/Reblocked/Reblocked.apk",
            profile_key="TEST_PROFILE",
            profile=None,
            version_name="1.0",
            version_code="1",
            apk_paths=["/system/app/Reblocked/Reblocked.apk"],
            split_count=1,
        ),
        artifacts=[],
        total_paths=1,
        policy_filtered_count=1,
        policy_filtered_reason="non_root_paths",
        skip_reason="policy_non_root",
    )
    monkeypatch.setattr(
        runner.package_refresh,
        "replan_package_after_stale_path",
        lambda **_kwargs: (refreshed_plan, ("refreshed_skip:policy_non_root",)),
    )

    results = runner.execute_harvest(
        serial="SERIAL123",
        adb_path="adb",
        dest_root=tmp_path / "SERIAL123" / "20260328",
        session_stamp="20260328",
        plans=[original_plan],
        config=object(),
        pull_mode="inventory",
    )

    assert len(results) == 1
    result = results[0]
    assert result.capture_status == "drifted"
    assert result.persistence_status == "not_requested"
    assert result.research_status == "ineligible"
    assert result.preflight_reason == "policy_non_root"
    assert result.skipped == ["policy_non_root"]
    assert result.errors == []
    assert result.drift_reasons == ["refreshed_skip:policy_non_root"]
    assert result.stale_replan_required is True
    assert result.stale_replan_outcome == "path_stale_blocked_before_pull"
    assert result.package_manifest_path is not None
    payload = result.package_manifest_path.read_text(encoding="utf-8")
    assert '"preflight_reason": "policy_non_root"' in payload
    assert '"capture_status": "drifted"' in payload
    assert '"policy_filtered_reason": "non_root_paths"' in payload


def test_execute_harvest_stops_early_when_device_becomes_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.common import HarvestOptions
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError, ArtifactPlan, InventoryRow, PackagePlan

    monkeypatch.setattr(
        runner,
        "load_options",
        lambda config, *, pull_mode: HarvestOptions(
            write_db=False,
            write_meta=False,
            pull_mode=pull_mode,
        ),
    )
    monkeypatch.setattr(diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(runner, "get_run_logger", lambda *args, **kwargs: _FakeRunLogger())
    monkeypatch.setattr(runner.log, "harvest_adapter", lambda *args, **kwargs: _FakeAdapter())
    monkeypatch.setattr(runner.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "info", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "error", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "_quiet_mode", lambda: True)
    monkeypatch.setattr(runner, "_compact_mode", lambda: True)

    calls: list[str] = []

    def _fake_pull(**kwargs):
        calls.append(kwargs["source_path"])
        return ArtifactError(source_path=kwargs["source_path"], reason="device_unavailable")

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    def _plan(package_name: str) -> PackagePlan:
        inventory = InventoryRow(
            raw={},
            package_name=package_name,
            app_label=package_name,
            installer="com.android.vending",
            category=None,
            primary_path=f"/data/app/{package_name}/base.apk",
            profile_key="TEST_PROFILE",
            profile=None,
            version_name="1.0",
            version_code="1",
            apk_paths=[f"/data/app/{package_name}/base.apk"],
            split_count=1,
        )
        return PackagePlan(
            inventory=inventory,
            artifacts=[
                ArtifactPlan(
                    source_path=f"/data/app/{package_name}/base.apk",
                    artifact="base",
                    file_name=f"{package_name.replace('.', '_')}__base.apk",
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
        plans=[_plan("com.example.one"), _plan("com.example.two")],
        config=object(),
        pull_mode="inventory",
    )

    assert len(results) == 1
    assert results[0].errors[0].reason == "device_unavailable"
    assert calls == ["/data/app/com.example.one/base.apk"]
    assert "ADB device unavailable; stopping harvest early." in capsys.readouterr().out


def test_execute_harvest_marks_stale_replan_failure_explicitly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.common import HarvestOptions
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError, ArtifactPlan, InventoryRow, PackagePlan

    monkeypatch.setattr(
        runner,
        "load_options",
        lambda config, *, pull_mode: HarvestOptions(
            write_db=False,
            write_meta=False,
            pull_mode=pull_mode,
        ),
    )
    monkeypatch.setattr(diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(runner, "get_run_logger", lambda *args, **kwargs: _FakeRunLogger())
    monkeypatch.setattr(runner.log, "harvest_adapter", lambda *args, **kwargs: _FakeAdapter())
    monkeypatch.setattr(runner.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "info", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "error", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "resolve_storage_root", lambda: ("test-host", tmp_path.as_posix()))
    monkeypatch.setattr(runner, "_quiet_mode", lambda: True)
    monkeypatch.setattr(runner, "_compact_mode", lambda: True)
    monkeypatch.setattr(
        runner,
        "adb_pull",
        lambda **kwargs: ArtifactError(source_path=kwargs["source_path"], reason="path_stale"),
    )
    monkeypatch.setattr(
        runner.package_refresh,
        "replan_package_after_stale_path",
        lambda **_kwargs: (None, ("package_refresh_failed",)),
    )

    inventory = InventoryRow(
        raw={},
        package_name="com.example.failedreplan",
        app_label="Failed Replan",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.failedreplan/base.apk",
        profile_key="TEST_PROFILE",
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.failedreplan/base.apk"],
        split_count=1,
    )
    plan = PackagePlan(
        inventory=inventory,
        artifacts=[
            ArtifactPlan(
                source_path="/data/app/com.example.failedreplan/base.apk",
                artifact="base",
                file_name="com_example_failedreplan_1__base.apk",
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
    result = results[0]
    assert result.stale_replan_required is True
    assert result.stale_replan_outcome == "path_stale_replan_failed"
    assert result.errors[0].reason == "package_replan_failed_after_stale_path"


def test_print_progress_line_separates_reviewed_eligible_attempted_and_blocked(capsys) -> None:
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import InventoryRow, PackagePlan, PullResult

    inventory = InventoryRow(
        raw={},
        package_name="com.example.progress",
        app_label="Progress App",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.progress/base.apk",
        profile_key=None,
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.progress/base.apk"],
        split_count=1,
    )
    result = PullResult(plan=PackagePlan(inventory=inventory, artifacts=[], total_paths=1))
    runner._print_progress_line(
        result,
        {
            "packages_total": 578,
            "packages_reviewed": 120,
            "packages_eligible": 152,
            "packages_attempted": 31,
            "packages_harvested": 28,
            "packages_skipped": 89,
            "packages_runtime_skipped": 3,
            "packages_replanned": 2,
            "packages_replan_failed": 1,
            "packages_partial": 0,
            "packages_failed": 0,
            "packages_drifted": 3,
        },
        package_index=31,
        package_total=152,
        force=True,
    )
    out = capsys.readouterr().out
    assert "reviewed 120/578" in out
    assert "eligible 152" in out
    assert "attempted 31" in out
    assert "harvested 28" in out
    assert "blocked before pull 89" in out
    assert "replanned 2 (failed 1)" in out
    assert "blocked reviewed" not in out


def test_update_package_outcome_tolerates_legacy_pull_result_without_replan_fields() -> None:
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import InventoryRow, PackagePlan, PullResult

    inventory = InventoryRow(
        raw={},
        package_name="com.example.legacyresult",
        app_label="Legacy Result",
        installer="com.android.vending",
        category=None,
        primary_path="/data/app/com.example.legacyresult/base.apk",
        profile_key=None,
        profile=None,
        version_name="1.0",
        version_code="1",
        apk_paths=["/data/app/com.example.legacyresult/base.apk"],
        split_count=1,
    )
    result = PullResult(
        plan=PackagePlan(inventory=inventory, artifacts=[], total_paths=1),
        capture_status="clean",
    )
    delattr(result, "stale_replan_required")
    delattr(result, "stale_replan_outcome")

    stats = {
        "packages_reviewed": 0,
        "packages_attempted": 0,
        "packages_harvested": 0,
        "packages_runtime_skipped": 0,
        "packages_path_stale": 0,
        "packages_replanned": 0,
        "packages_replan_success": 0,
        "packages_replan_failed": 0,
        "packages_drifted": 0,
        "packages_partial": 0,
        "packages_failed": 0,
        "packages_clean": 0,
        "packages_mirror_failed": 0,
    }

    runner._update_package_outcome(stats, result)

    assert stats["packages_reviewed"] == 1
    assert stats["packages_attempted"] == 1
    assert stats["packages_clean"] == 1
    assert stats["packages_path_stale"] == 0
    assert stats["packages_replanned"] == 0
