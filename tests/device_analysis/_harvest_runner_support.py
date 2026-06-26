from __future__ import annotations

from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.common import HarvestOptions
from scytaledroid.DeviceAnalysis.harvest.models import ArtifactPlan, InventoryRow, PackagePlan


class FakeAdapter:
    extra: dict[str, object] = {}

    def info(self, *args, **kwargs) -> None:
        pass

    def warning(self, *args, **kwargs) -> None:
        pass

    def error(self, *args, **kwargs) -> None:
        pass


class FakeRunLogger:
    def info(self, *args, **kwargs) -> None:
        pass


def isolate_storage_contract(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")
    monkeypatch.setattr(app_config, "OUTPUT_DIR", "output")


def patch_runner_common(
    monkeypatch,
    *,
    runner,
    diagnostics,
    tmp_path: Path,
    write_db: bool = False,
    write_meta: bool = False,
    pull_mode: str = "inventory",
    with_storage_root: bool = True,
) -> None:
    monkeypatch.setattr(
        runner,
        "load_options",
        lambda config, *, pull_mode: HarvestOptions(
            write_db=write_db,
            write_meta=write_meta,
            pull_mode=pull_mode,
        ),
    )
    monkeypatch.setattr(diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(runner, "get_run_logger", lambda *args, **kwargs: FakeRunLogger())
    monkeypatch.setattr(runner.log, "harvest_adapter", lambda *args, **kwargs: FakeAdapter())
    monkeypatch.setattr(runner.log, "close_harvest_adapter", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "info", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.log, "error", lambda *args, **kwargs: None)
    if with_storage_root:
        monkeypatch.setattr(runner, "resolve_storage_root", lambda: ("test-host", tmp_path.as_posix()))
    monkeypatch.setattr(runner, "_quiet_mode", lambda: True)
    monkeypatch.setattr(runner, "_compact_mode", lambda: True)


def make_inventory_row(
    *,
    package_name: str,
    app_label: str | None = None,
    installer: str | None = "com.android.vending",
    primary_path: str | None = None,
    profile_key: str | None = "TEST_PROFILE",
    version_name: str = "1.0",
    version_code: str = "1",
    apk_paths: list[str] | None = None,
    split_count: int | None = None,
    raw: dict | None = None,
) -> InventoryRow:
    if primary_path is None:
        primary_path = f"/data/app/{package_name}/base.apk"
    if apk_paths is None:
        apk_paths = [primary_path]
    if split_count is None:
        split_count = len(apk_paths)
    return InventoryRow(
        raw=raw or {},
        package_name=package_name,
        app_label=app_label or package_name,
        installer=installer,
        category=None,
        primary_path=primary_path,
        profile_key=profile_key,
        profile=None,
        version_name=version_name,
        version_code=version_code,
        apk_paths=apk_paths,
        split_count=split_count,
    )


def make_artifact_plan(
    *,
    source_path: str,
    artifact: str,
    file_name: str,
    is_split_member: bool = False,
) -> ArtifactPlan:
    return ArtifactPlan(
        source_path=source_path,
        artifact=artifact,
        file_name=file_name,
        is_split_member=is_split_member,
    )


def make_package_plan(
    *,
    inventory: InventoryRow,
    artifacts: list[ArtifactPlan],
    total_paths: int | None = None,
    policy_filtered_count: int = 0,
    policy_filtered_reason: str | None = None,
    skip_reason: str | None = None,
) -> PackagePlan:
    return PackagePlan(
        inventory=inventory,
        artifacts=artifacts,
        total_paths=total_paths if total_paths is not None else len(artifacts),
        policy_filtered_count=policy_filtered_count,
        policy_filtered_reason=policy_filtered_reason,
        skip_reason=skip_reason,
    )
