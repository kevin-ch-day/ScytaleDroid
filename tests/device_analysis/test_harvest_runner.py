from __future__ import annotations

from pathlib import Path

import pytest


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
    assert calls == [
        ("app_definition", "com.example.app", "TEST_PROFILE"),
        ("apk_record", "com.example.app", results[0].ok[0].sha256),
        ("artifact_path", 23, 7, "SERIAL123/20260328/com.example.app/com_example_app_1__base.apk"),
        ("source_path", 23, "/data/app/com.example.app/base.apk"),
    ]
