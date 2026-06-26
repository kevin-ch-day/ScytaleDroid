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


def test_execute_harvest_replans_stale_package_and_recovers_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path)
    attempts = {"count": 0}

    def _fake_pull(**kwargs):
        dest_path = kwargs["dest_path"]
        attempts["count"] += 1
        if attempts["count"] == 1:
            return ArtifactError(source_path=kwargs["source_path"], reason="path_stale")
        dest_path.write_bytes(b"apk-bytes")
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    inventory = make_inventory_row(
        package_name="com.example.stale",
        app_label="Stale App",
        primary_path="/data/app/com.example.stale/base.apk",
        apk_paths=["/data/app/com.example.stale/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.stale/base.apk",
                artifact="base",
                file_name="com_example_stale_1__base.apk",
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

    result = results[0]
    assert attempts["count"] == 2
    assert result.capture_status == "clean"
    assert result.persistence_status == "not_requested"
    assert result.research_status == "pending_audit"
    assert result.errors == []
    assert result.stale_replan_required is True
    assert result.stale_replan_outcome == "path_stale_refreshed_and_retried"
    assert result.stale_replan_details["attempted_source_path"] == "/data/app/com.example.stale/base.apk"
    assert result.stale_replan_details["refreshed_apk_paths"] == ["/data/app/com.example.stale/base.apk"]
    assert result.stale_replan_details["refresh_failed"] is False
    assert len(result.ok) == 1
    payload = result.package_manifest_path.read_text(encoding="utf-8")
    assert '"stale_replan": {' in payload
    assert '"required": true' in payload
    assert '"outcome": "path_stale_refreshed_and_retried"' in payload


def test_pull_and_record_marks_stale_path_as_retryable_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.common import DedupeTracker, HarvestOptions
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError

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

    inventory = make_inventory_row(
        package_name="com.example.retry",
        app_label="Retry App",
        primary_path="/data/app/com.example.retry/base.apk",
        apk_paths=["/data/app/com.example.retry/base.apk"],
    )
    plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.retry/base.apk",
                artifact="base",
                file_name="com_example_retry_1__base.apk",
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
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path)

    def _fake_pull(**kwargs):
        dest_path = kwargs["dest_path"]
        if kwargs["source_path"].endswith("/base.apk"):
            dest_path.write_bytes(b"base-apk")
            return True
        return ArtifactError(source_path=kwargs["source_path"], reason="path_stale")

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    inventory = make_inventory_row(
        package_name="com.example.drift",
        app_label="Drift App",
        primary_path="/data/app/com.example.drift/base.apk",
        apk_paths=[
            "/data/app/com.example.drift/base.apk",
            "/data/app/com.example.drift/split_config.arm64_v8a.apk",
        ],
        split_count=2,
    )
    original_plan = make_package_plan(
        inventory=inventory,
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.drift/base.apk",
                artifact="base",
                file_name="com_example_drift_1__base.apk",
            ),
            make_artifact_plan(
                source_path="/data/app/com.example.drift/split_config.arm64_v8a.apk",
                artifact="split_config.arm64_v8a",
                file_name="com_example_drift_1__split_config.arm64_v8a.apk",
                is_split_member=True,
            ),
        ],
        total_paths=2,
    )
    drifted_plan = make_package_plan(
        inventory=make_inventory_row(
            package_name="com.example.drift",
            app_label="Drift App",
            primary_path="/data/app/com.example.drift/base.apk",
            version_name="1.1",
            version_code="2",
            apk_paths=[
                "/data/app/com.example.drift/base.apk",
                "/data/app/com.example.drift/split_config.xxhdpi.apk",
            ],
            split_count=2,
        ),
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.drift/base.apk",
                artifact="base",
                file_name="com_example_drift_2__base.apk",
            ),
            make_artifact_plan(
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

    result = results[0]
    assert result.capture_status == "drifted"
    assert result.persistence_status == "not_requested"
    assert result.research_status == "ineligible"
    assert sorted(result.drift_reasons) == ["artifact_set_changed", "version_code_changed"]
    assert result.stale_replan_required is True
    assert result.stale_replan_outcome == "path_stale_package_updated_since_inventory"
    assert result.stale_replan_details["refreshed_version_code"] == "2"
    assert sorted(result.stale_replan_details["drift_reasons"]) == [
        "artifact_set_changed",
        "version_code_changed",
    ]
    assert len(result.ok) == 1
    assert len(result.errors) == 1
    assert result.errors[0].reason == "package_drift_detected_after_partial_pull"
    payload = result.package_manifest_path.read_text(encoding="utf-8")
    assert '"capture_status": "drifted"' in payload
    assert '"drift_reasons": [' in payload
    assert '"outcome": "path_stale_package_updated_since_inventory"' in payload


def test_execute_harvest_surfaces_refreshed_skip_reason_after_stale_path_replan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path)
    monkeypatch.setattr(
        runner,
        "adb_pull",
        lambda **kwargs: ArtifactError(source_path=kwargs["source_path"], reason="path_stale"),
    )

    original_plan = make_package_plan(
        inventory=make_inventory_row(
            package_name="com.example.reblocked",
            app_label="Reblocked App",
            primary_path="/data/app/com.example.reblocked/base.apk",
            apk_paths=["/data/app/com.example.reblocked/base.apk"],
        ),
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.reblocked/base.apk",
                artifact="base",
                file_name="com_example_reblocked_1__base.apk",
            )
        ],
        total_paths=1,
    )
    refreshed_plan = make_package_plan(
        inventory=make_inventory_row(
            package_name="com.example.reblocked",
            app_label="Reblocked App",
            primary_path="/system/app/Reblocked/Reblocked.apk",
            apk_paths=["/system/app/Reblocked/Reblocked.apk"],
            raw={"path_fidelity": "bulk_base_only"},
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
    assert result.stale_replan_details["refreshed_skip_reason"] == "policy_non_root"
    assert result.stale_replan_details["refreshed_apk_paths"] == ["/system/app/Reblocked/Reblocked.apk"]
    payload = result.package_manifest_path.read_text(encoding="utf-8")
    assert '"preflight_reason": "policy_non_root"' in payload
    assert '"capture_status": "drifted"' in payload
    assert '"policy_filtered_reason": "non_root_paths"' in payload
    assert '"outcome": "path_stale_blocked_before_pull"' in payload


def test_execute_harvest_classifies_path_set_change_without_version_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path)

    def _fake_pull(**kwargs):
        dest_path = kwargs["dest_path"]
        if kwargs["source_path"].endswith("/base_old.apk"):
            return ArtifactError(source_path=kwargs["source_path"], reason="path_stale")
        dest_path.write_bytes(b"apk-bytes")
        return True

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    original_plan = make_package_plan(
        inventory=make_inventory_row(
            package_name="com.example.pathchange",
            app_label="Path Change",
            primary_path="/data/app/com.example.pathchange/base_old.apk",
            apk_paths=["/data/app/com.example.pathchange/base_old.apk"],
        ),
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.pathchange/base_old.apk",
                artifact="base",
                file_name="com_example_pathchange_1__base_old.apk",
            )
        ],
        total_paths=1,
    )
    refreshed_plan = make_package_plan(
        inventory=make_inventory_row(
            package_name="com.example.pathchange",
            app_label="Path Change",
            primary_path="/data/app/com.example.pathchange/base_new.apk",
            apk_paths=["/data/app/com.example.pathchange/base_new.apk"],
        ),
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.pathchange/base_new.apk",
                artifact="base",
                file_name="com_example_pathchange_1__base_new.apk",
            )
        ],
        total_paths=1,
    )
    monkeypatch.setattr(
        runner.package_refresh,
        "replan_package_after_stale_path",
        lambda **_kwargs: (refreshed_plan, ("artifact_set_changed",)),
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

    result = results[0]
    assert result.capture_status == "clean"
    assert result.stale_replan_outcome == "path_stale_package_paths_changed_since_inventory"
    assert result.stale_replan_details["refreshed_primary_path"] == "/data/app/com.example.pathchange/base_new.apk"
    assert result.stale_replan_details["recovered_inventory_drift"] is True
    assert result.research_status == "pending_audit"
    assert result.drift_reasons == []


def test_execute_harvest_recovers_cleanly_when_split_membership_changes_after_base_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path)

    def _fake_pull(**kwargs):
        source_path = kwargs["source_path"]
        dest_path = kwargs["dest_path"]
        if source_path.endswith("/base.apk"):
            dest_path.write_bytes(b"base")
            return True
        if source_path.endswith("/split_old.apk"):
            return ArtifactError(source_path=source_path, reason="path_stale")
        if source_path.endswith("/split_new.apk"):
            dest_path.write_bytes(b"split")
            return True
        raise AssertionError(f"unexpected path {source_path}")

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    original_plan = make_package_plan(
        inventory=make_inventory_row(
            package_name="com.example.compat",
            app_label="Compat App",
            primary_path="/data/app/com.example.compat/base.apk",
            apk_paths=[
                "/data/app/com.example.compat/base.apk",
                "/data/app/com.example.compat/split_old.apk",
            ],
            split_count=2,
        ),
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.compat/base.apk",
                artifact="base",
                file_name="com_example_compat_1__base.apk",
            ),
            make_artifact_plan(
                source_path="/data/app/com.example.compat/split_old.apk",
                artifact="split_old",
                file_name="com_example_compat_1__split_old.apk",
                is_split_member=True,
            ),
        ],
        total_paths=2,
    )
    refreshed_plan = make_package_plan(
        inventory=make_inventory_row(
            package_name="com.example.compat",
            app_label="Compat App",
            primary_path="/data/app/com.example.compat/base.apk",
            apk_paths=[
                "/data/app/com.example.compat/base.apk",
                "/data/app/com.example.compat/split_new.apk",
            ],
            split_count=2,
        ),
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.compat/base.apk",
                artifact="base",
                file_name="com_example_compat_1__base.apk",
            ),
            make_artifact_plan(
                source_path="/data/app/com.example.compat/split_new.apk",
                artifact="split_new",
                file_name="com_example_compat_1__split_new.apk",
                is_split_member=True,
            ),
        ],
        total_paths=2,
    )
    monkeypatch.setattr(
        runner.package_refresh,
        "replan_package_after_stale_path",
        lambda **_kwargs: (refreshed_plan, ("artifact_set_changed",)),
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

    result = results[0]
    assert result.capture_status == "clean"
    assert result.research_status == "pending_audit"
    assert result.drift_reasons == []
    assert result.errors == []
    assert result.stale_replan_outcome == "path_stale_package_paths_changed_since_inventory"
    assert result.stale_replan_details["recovered_inventory_drift"] is True
    assert len(result.ok) == 2


def test_execute_harvest_marks_stale_replan_failure_explicitly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path)
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

    plan = make_package_plan(
        inventory=make_inventory_row(
            package_name="com.example.failedreplan",
            app_label="Failed Replan",
            primary_path="/data/app/com.example.failedreplan/base.apk",
            apk_paths=["/data/app/com.example.failedreplan/base.apk"],
        ),
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.failedreplan/base.apk",
                artifact="base",
                file_name="com_example_failedreplan_1__base.apk",
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

    result = results[0]
    assert result.stale_replan_required is True
    assert result.stale_replan_outcome == "path_stale_replan_failed"
    assert result.stale_replan_details["refresh_failed"] is True
    assert result.stale_replan_details["drift_reasons"] == ["package_refresh_failed"]
    assert result.errors[0].reason == "package_replan_failed_after_stale_path"


def test_execute_harvest_replans_split_package_without_retrying_written_base(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scytaledroid.Database.db_utils import diagnostics
    from scytaledroid.DeviceAnalysis.harvest import runner
    from scytaledroid.DeviceAnalysis.harvest.models import ArtifactError

    patch_runner_common(monkeypatch, runner=runner, diagnostics=diagnostics, tmp_path=tmp_path)
    calls: list[str] = []

    def _fake_pull(**kwargs):
        source_path = kwargs["source_path"]
        dest_path = kwargs["dest_path"]
        calls.append(source_path)
        if source_path.endswith("/base.apk"):
            dest_path.write_bytes(b"base")
            return True
        if source_path.endswith("/split_old.apk"):
            return ArtifactError(source_path=source_path, reason="path_stale")
        if source_path.endswith("/split_new.apk"):
            dest_path.write_bytes(b"split")
            return True
        raise AssertionError(f"unexpected path {source_path}")

    monkeypatch.setattr(runner, "adb_pull", _fake_pull)

    original_plan = make_package_plan(
        inventory=make_inventory_row(
            package_name="com.example.splitreplan",
            app_label="Split Replan",
            primary_path="/data/app/com.example.splitreplan/base.apk",
            apk_paths=[
                "/data/app/com.example.splitreplan/base.apk",
                "/data/app/com.example.splitreplan/split_old.apk",
            ],
            split_count=2,
        ),
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.splitreplan/base.apk",
                artifact="base",
                file_name="com_example_splitreplan_1__base.apk",
            ),
            make_artifact_plan(
                source_path="/data/app/com.example.splitreplan/split_old.apk",
                artifact="split_config.xhdpi",
                file_name="com_example_splitreplan_1__split_config.xhdpi.apk",
                is_split_member=True,
            ),
        ],
        total_paths=2,
    )
    refreshed_plan = make_package_plan(
        inventory=make_inventory_row(
            package_name="com.example.splitreplan",
            app_label="Split Replan",
            primary_path="/data/app/com.example.splitreplan/base.apk",
            apk_paths=[
                "/data/app/com.example.splitreplan/base.apk",
                "/data/app/com.example.splitreplan/split_new.apk",
            ],
            split_count=2,
        ),
        artifacts=[
            make_artifact_plan(
                source_path="/data/app/com.example.splitreplan/base.apk",
                artifact="base",
                file_name="com_example_splitreplan_1__base.apk",
            ),
            make_artifact_plan(
                source_path="/data/app/com.example.splitreplan/split_new.apk",
                artifact="split_config.xhdpi",
                file_name="com_example_splitreplan_1__split_config.xhdpi.apk",
                is_split_member=True,
            ),
        ],
        total_paths=2,
    )
    monkeypatch.setattr(
        runner.package_refresh,
        "replan_package_after_stale_path",
        lambda **_kwargs: (refreshed_plan, tuple()),
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

    result = results[0]
    assert calls == [
        "/data/app/com.example.splitreplan/base.apk",
        "/data/app/com.example.splitreplan/split_old.apk",
        "/data/app/com.example.splitreplan/split_new.apk",
    ]
    assert result.capture_status == "clean"
    assert result.stale_replan_required is True
    assert result.stale_replan_outcome == "path_stale_refreshed_and_retried"
    assert result.stale_replan_details["refreshed_apk_paths"] == [
        "/data/app/com.example.splitreplan/base.apk",
        "/data/app/com.example.splitreplan/split_new.apk",
    ]
    assert len(result.ok) == 2
